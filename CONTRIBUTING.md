# Contributing

Find an area you can help with and do it. Open source is about collaboration and open participation. Try to make your code look like what already exists and submit a pull request.

Additional tests are rewarded with an immense amount of positive karma.

More documentation or updates/fixes to existing documentation are also very welcome.

# PR Guidelines

We generally prefer you to PR your work earlier rather than later. This ensures everyone else has a better idea of what's being worked on, and can help reduce wasted effort. If work on your PR has just begun, please feel free to create the PR with [WIP] (work in progress) in the PR title, and let us know when it's ready for review in the comments.

## Testing

Run all tests with `cargo test --all` and please remember to test locally before creating a PR on github.

### The Azure build pipeline

After creating a PR on github, the code will be tested automatically by the Azure build pipeline on multiple platforms. You can see the output here: https://dev.azure.com/bitcoinmw/bitcoinmw/_build

If you break the build, please revert your code right away and then address the bug and recheck in. We like to keep the build working at all times.

### Building quality

The most important thing you can do alongside - or even before - changing code, is adding tests for how bitcoinmw should and should not work. See the various `tests` folders and derive test that are already there in bitcoinmw.

After that, if you want to raise code quality another level, you can use `cargo check`, `cargo cov test` and `cargo tarpaulin`. Install them with `cargo install cargo-check cargo-cov; RUSTFLAGS="--cfg procmacro2_semver_exempt" cargo install cargo-tarpaulin`. Run with `cargo cov test` and `cargo tarpaulin`. The quality check tools are often integrated with `rustc` and as a side-effect only activated when some code is compiled. Because of this, if you want a complete check you'll need to `cargo clean` first.

We have some details on [code coverage and historical numbers on the wiki](https://github.com/mimblewimble/docs/wiki/Code-coverage-and-metrics).

# Pull-Request Title Prefix

**Note**: *[draft part! to be reviewed and discussed]*

Please consider putting one of the following prefixes in the title of your pull-request:
- **feat**:     A new feature
- **fix**:      A bug fix
- **docs**:     Documentation only changes
- **style**:    Formatting, missing semi-colons, white-space, etc
- **refactor**: A code change that neither fixes a bug nor adds a feature
- **perf**:     A code change that improves performance
- **test**:     Adding missing tests
- **chore**:    Maintain. Changes to the build process or auxiliary tools/libraries/documentation

For example: `fix: a panick on xxx when bitcoinmw exiting`. Please don't worry if you can't find a suitable prefix, this's just optional, not mandatory.

# BitcoinMW Style Guide

This project uses `rustfmt` to maintain consistent formatting. We've made sure that rustfmt runs **automatically**, but you must install rustfmt manually first.

## Install rustfmt

**Note**: To work with bitcoinmw you must use `rustup`. Linux package managers typically carry a too old rust version.
See [build docs](doc/build.md) for more info.

First ensure you have a new enough rustfmt:
```
rustup update
rustup component add rustfmt
rustfmt --version
```

and verify you did get version `rustfmt 1.0.0-stable (43206f4 2018-11-30)` or newer.

Then run `cargo build` to activate a git `pre-commit` hook that automates the rustfmt usage so you don't have to worry much about it. Read on for how to make this work in your advantage.

## Creating git commits

When you make a commit, rustfmt will be run and we also **automatically** reformat the .rs files that your commit is touching.

### Manually configuring git hooks

If you are developing new or changed git hooks, or are curious, you can config hooks manually like this `git config core.hooksPath ./.hooks` and to verify the effect do `git config --list | grep hook` and expect the output to be `core.hookspath=./.hooks`

### Running rustfmt manually

Not recommended, but you can run rustfmt on a file like this: `rustfmt client.rs`

**Notes**:
1. *Please keep rustfmt corrections in a separate commit. This is best practice and makes reviewing and merging your contribution work better.*

2. *If unsure about code formatting, it's just fine if you ignore and discard any rustfmt changes. It's only a nice-to-have. Your contribution and code changes is the priority here. Hope you're happy to contribute on this open source project!*

3. Please don't ~~`cargo +nightly fmt`~~ because all bitcoinmw developers are using stable rustfmt. Also please don't rustfmt files that your code changes does not touch to avoid causing merge conflicts.

## Thanks for any contribution

Even one word correction are welcome! Our objective is to encourage you to get interested in BitcoinMW and contribute in any way possible. Thanks for any help!
