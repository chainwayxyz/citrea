{
  description = "Reproducible build for Citrea fullnode binaries";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";

    crane.url = "github:ipetkov/crane";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, crane, rust-overlay, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ] (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };

        rustToolchain = pkgs.rust-bin.stable."1.97.1".minimal.override {
          extensions = [ "rust-src" "clippy" "rustfmt" ];
        };

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # Workspace root is one level up from this flake (which lives in `nix/`).
        workspaceRoot = ../.;

        # Release artifacts run outside the Nix store, so Linux binaries need the
        # distro-standard dynamic loader instead of Nix's glibc interpreter path.
        linuxElfInterpreter =
          if system == "x86_64-linux" then
            "/lib64/ld-linux-x86-64.so.2"
          else if system == "aarch64-linux" then
            "/lib/ld-linux-aarch64.so.1"
          else if pkgs.stdenv.hostPlatform.isLinux then
            throw "Unsupported Linux release system: ${system}"
          else
            "";

        # Source filtering: Rust sources + non-Rust assets the workspace consumes at
        # compile time. Anything else is excluded so deps-only caching isn't invalidated
        # by unrelated changes.
        # - resources/, guests/: workspace layout + sp1 ELFs embedded via include_bytes!
        # - README.md: several crates use #![doc = include_str!("../README.md")]
        # - crates/evm/src/evm/**/*.{json,abi,bin}: consumed by sol!() and include_str!()
        #   (system_contracts/out/*.sol/*.json artifacts and test_data/*.{abi,bin})
        src = pkgs.lib.cleanSourceWith {
          src = workspaceRoot;
          filter = path: type:
            (craneLib.filterCargoSources path type)
            || (builtins.match ".*/(resources|guests)/.*" path != null)
            || (builtins.match ".*/README\\.md$" path != null)
            || (builtins.match ".*/crates/evm/src/evm/.*\\.(json|abi|bin)$" path != null);
        };

        # SP1's runner otherwise resolves its packaged Cargo.lock and launches a
        # nested build outside our workspace. Use our lockfile and vendor set for
        # both metadata and compilation, and preserve Nix's path remapping in the
        # helper embedded into the final binary.
        cargoVendorDir = craneLib.vendorCargoDeps {
          inherit src;
          overrideVendorCargoPackage = package: drv:
            if package.name == "sp1-core-executor-runner" then
              drv.overrideAttrs (old: {
                postPatch = (old.postPatch or "") + ''
                  substituteInPlace build.rs \
                    --replace-fail 'let metadata = MetadataCommand::new().exec().expect("Failed to run cargo metadata");' \
                      'let manifest = env::var("CITREA_WORKSPACE_MANIFEST").expect("Nix workspace manifest");
                      let metadata = MetadataCommand::new().manifest_path(&manifest).other_options(vec!["--locked".into(), "--offline".into()]).exec().expect("Failed to run cargo metadata");' \
                    --replace-fail 'cmd.arg("build").arg("--manifest-path").arg(inner_manifest_path);' \
                      'cmd.arg("build").arg("--manifest-path").arg(&manifest).arg("--package").arg(INNER_CRATE_NAME).arg("--locked").arg("--offline");' \
                    --replace-fail 'cmd.env_remove("RUSTFLAGS");' \
                      'cmd.env("RUSTFLAGS", env::var("RUSTFLAGS").unwrap_or_default());'
                '' + pkgs.lib.optionalString (system == "x86_64-linux") ''
                  # The x86 executor extracts this embedded ELF at runtime. Give
                  # it the same portable loader as the published node binaries
                  # before SP1 hashes and embeds its bytes.
                  substituteInPlace build.rs \
                    --replace-fail '// 6. Calculates and passes binary hash' \
                      'assert!(Command::new("${pkgs.patchelf}/bin/patchelf").arg("--set-interpreter").arg("${linuxElfInterpreter}").arg(&bin_path).status().expect("Patch embedded runner interpreter").success());
                      // 6. Calculates and passes binary hash'
                '';
              })
            else drv;
        };

        commonArgs = {
          inherit src cargoVendorDir;
          pname = "citrea";
          version =
            let
              cargoToml = builtins.fromTOML (builtins.readFile (workspaceRoot + "/Cargo.toml"));
            in
              cargoToml.workspace.package.version;

          strictDeps = true;

          nativeBuildInputs = with pkgs; [
            pkg-config
            protobuf
            cmake
            clang
            llvmPackages.libclang
            perl # needed by ring crate
            rustPlatform.bindgenHook
          ];

          buildInputs = with pkgs; [
            openssl
            zlib
            bzip2
            lz4
          ];

          # Reproducibility
          SKIP_GUEST_BUILD = "1";
          SOURCE_DATE_EPOCH = "0";
          LC_ALL = "C";
          TZ = "UTC";
          ZERO_AR_DATE = "1";
          CARGO_INCREMENTAL = "0";
          CARGO_NET_OFFLINE = "true";
          # Avoid host-dependent jemalloc rtree sizing on machines with 5-level paging.
          JEMALLOC_SYS_WITH_LG_VADDR = "48";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          PROTOC_INCLUDE = "${pkgs.protobuf}/include";

          # GCC 14 promoted -Wint-conversion to an error by default, which breaks
          # the bundled jemalloc in tikv-jemalloc-sys 0.6.0 (its strerror_r call
          # predates the XSI-compliant prototype). Demote it back to a warning.
          #
          # Nix's cc-wrapper always defines _FORTIFY_SOURCE, and glibc emits a
          # #warning for it when a unit is compiled at -O0. jemalloc's configure
          # probes strerror_r with -Werror, so that warning fails the probe, and
          # tikv-jemalloc-sys 0.6.1 turned the failed probe into a hard error
          # ("cannot determine return type of strerror_r"). Keep it a warning.
          NIX_CFLAGS_COMPILE = "-Wno-int-conversion -Wno-error=cpp";

          RUSTFLAGS = builtins.concatStringsSep " " [
            "--remap-path-prefix=${src}=/build/source"
            "--remap-path-prefix=/build=/build"
          ];

          cargoExtraArgs = "--locked";

          preBuild = ''
            export CITREA_WORKSPACE_MANIFEST="$PWD/Cargo.toml"
            export RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$(pwd)=/build/source"
          '' + pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
            export RUSTFLAGS="$RUSTFLAGS -C link-arg=-Wl,-oso_prefix,$(realpath $NIX_BUILD_TOP)/"
            export NIX_CFLAGS_COMPILE="$NIX_CFLAGS_COMPILE -fdebug-prefix-map=$NIX_BUILD_TOP=/build"
          '';
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

      in {
        packages = {
          citrea = craneLib.buildPackage (commonArgs // {
            inherit cargoArtifacts;
            cargoExtraArgs = "--locked --package citrea --package citrea-cli";
            doCheck = false;

            postInstall = ''
              strip $out/bin/citrea
              strip $out/bin/citrea-cli
            '';

            postFixup =
              pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin ''
                otool="${pkgs.darwin.cctools}/bin/otool"
                install_name_tool="${pkgs.darwin.cctools}/bin/install_name_tool"
                codesign_allocate="${pkgs.darwin.binutils.bintools}/bin/codesign_allocate"
                codesign="${pkgs.darwin.sigtool}/bin/codesign"
                for bin in $out/bin/citrea $out/bin/citrea-cli; do
                  chmod +w "$bin"

                  LIBICONV_PATH="$("$otool" -L "$bin" | awk '/libiconv\.2\.dylib/{print $1; exit}')"
                  if [ -n "$LIBICONV_PATH" ]; then
                    "$install_name_tool" \
                      -change "$LIBICONV_PATH" /usr/lib/libiconv.2.dylib \
                      "$bin"
                  fi

                  CODESIGN_ALLOCATE="$codesign_allocate" "$codesign" -f -s - "$bin"
                  chmod 555 "$bin"
                done
              ''
              + pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
                patchelf="${pkgs.patchelf}/bin/patchelf"
                for bin in $out/bin/citrea $out/bin/citrea-cli; do
                  chmod +w "$bin"

                  "$patchelf" --set-interpreter "${linuxElfInterpreter}" "$bin"
                  actual_interpreter="$("$patchelf" --print-interpreter "$bin")"
                  if [ "$actual_interpreter" != "${linuxElfInterpreter}" ]; then
                    echo "failed to patch ELF interpreter for $bin" >&2
                    exit 1
                  fi

                  chmod 555 "$bin"
                done
              '';
          });

          default = self.packages.${system}.citrea;
        };

        devShells.default = craneLib.devShell {
          packages = with pkgs; [
            cargo-nextest
            rust-analyzer
          ];

          SKIP_GUEST_BUILD = "1";
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
        };
      }
    );
}
