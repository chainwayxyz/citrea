## How to contribute to Citrea

Thank you for your interest in contributing to Citrea! We accept and appreciate all kinds of contributions. Before moving on, we highly advise you to read this document to be an effective contributor.

## On questions

If you have some questions regarding the project or the repository, or if there are parts in the code that you could not understand, please visit our [Discord](https://discord.citrea.xyz). You can ask your technical questions regarding the project/repository in the #developer-chat there.

Using issues for questions creates lots of noise on the codebase, so we kindly ask you to follow this convention.

### Issues

If you see any problems regarding to code, or if you have any feature requests to be completed in the future, you may open an issue. However, before doing so, please search through the issues and pull requests to see if it's been done before to not to cause a duplicate issue.

We have two different issue templates, one for the bugs and one for the feature requests. Please open issues using these templates. If you believe that your issue does not cover all of the fields in these templates, you can skip or leave some fields short. However, in general, you should write all necessary details for others to understand or develop on top of that.

Along with that, we expect the issue owner to be active in discussions when necessary (i.e. when steps could not be reprocuded or request is not clear), so please be aware of that.

#### On typo fixes

We do not accept typo fixes as issues / pull requests as of now. If you want to contribute in that sense still, you may state it in our [Discord](https://discord.citrea.xyz).

### Pull Requests

Let's say you decided to contribute through the code. Great! Now, firstly, before forking the repository and starting to work - please check other issues & pull requests to see whether the particular part you're interested in has been

- Discussed
- Completed
- Abandoned (closed)

After that, you may either request a task for yourself from the issues, or open an issue and state that you want to work on it. We, as maintainers, will gladly assign that particular section to you.

#### Continous Integration

We have an integrated CI workflow in our repository, with Rust version set to stable. It runs the following on pull requests and pushes to the nightly branch:

| Check   | Command for you to run in local |
| ------- | ------------------------------- |
| Lint    | `SKIP_GUEST_BUILD=1 make lint`  |
| Tests   | `SKIP_GUEST_BUILD=1 make test`  |
| No-std  | `make check-no-std`             |
| Foundry | `forge test -vvv`               |

We kindly expect you to run these and check everything is correct on your side before opening a ready Pull Request. We do not merge things until these pass, as expected :) If you want to check more about this workflow, feel free the to check it from [**here**](https://github.com/chainwayxyz/citrea/blob/nightly/.github/workflows/checks.yml) .

#### Styling

There's also a Git Hook for you to run, in terms of styling. You can see / run it from [**here**](https://github.com/chainwayxyz/citrea/blob/nightly/.githooks/pre-commit).

### Code of Conduct

Our project complies with the [Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct) of Rust. We expect all contributors to agree on this before contributing to the repository.

### License

All contributions under this repository will be covered by the [GPLv3](https://github.com/chainwayxyz/citrea/blob/nightly/COPYING) License.
