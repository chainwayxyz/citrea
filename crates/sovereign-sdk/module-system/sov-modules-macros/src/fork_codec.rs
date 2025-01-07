use proc_macro2::Span;
use quote::quote;
use syn::{Data, DeriveInput, Error};

pub fn derive_fork_codec(input: DeriveInput) -> Result<proc_macro::TokenStream, Error> {
    // Extract the name of the enum
    let name = &input.ident;

    // Ensure it's an enum
    let Data::Enum(data_enum) = &input.data else {
        return Err(Error::new(
            Span::call_site(),
            "ForkCodec can only be derived for enums. Use borsh derive directly instead.",
        ));
    };

    // Extract variants
    let variants = &data_enum.variants;

    // Generate match arms for encode and decode
    let encode_arms = variants.iter().map(|variant| {
        let variant_name = &variant.ident;
        quote! {
            Self::#variant_name(inner) => borsh::to_vec(inner).map_err(|e| e.into()),
        }
    });

    let decode_arms = variants.iter().enumerate().map(|(index, variant)| {
        let variant_name = &variant.ident;
        quote! {
            #index => {
                let inner = borsh::from_slice(slice)?;
                Ok(Self::#variant_name(inner))
            }
        }
    });

    // Fallback for remaining SpecId variants
    let fallback_variant = &variants.last().unwrap().ident;
    let fallback_arm = quote! {
        _ => {
            let inner = borsh::from_slice(slice)?;
            Ok(Self::#fallback_variant(inner))
        }
    };

    // Generate the implementation
    let expanded = quote! {
        impl sov_rollup_interface::fork::ForkCodec for #name {
            fn encode(&self) -> anyhow::Result<Vec<u8>> {
                match self {
                    #(#encode_arms)*
                }
            }

            fn decode(bytes: impl AsRef<[u8]>, spec: sov_rollup_interface::spec::SpecId) -> anyhow::Result<Self> {
                let slice = bytes.as_ref();
                match spec as u8 as usize {
                    #(#decode_arms)*
                    #fallback_arm
                }
            }
        }
    };

    Ok(proc_macro::TokenStream::from(expanded))
}
