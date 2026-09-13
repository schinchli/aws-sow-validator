# Contributing Guidelines

Thank you for your interest in contributing. Whether it's a bug report, new
feature, correction, or additional documentation, we greatly value feedback and
contributions from the community.

Please read through this document before submitting any issues or pull requests
to ensure we have all the necessary information to effectively respond to your
bug report or contribution.

## Reporting Bugs/Feature Requests

We welcome you to use the GitHub issue tracker to report bugs or suggest features.

When filing an issue, please check existing open, or recently closed, issues to
make sure somebody else hasn't already reported the issue. Please try to include
as much information as you can. Details like these are incredibly useful:

- A reproducible test case or series of steps
- The version of the code being used
- The AWS region you deployed into
- Any modifications you've made relevant to the bug
- Anything unusual about your environment or deployment

## Contributing via Pull Requests

Before sending us a pull request, please ensure that:

1. You are working against the latest source on the `main` branch.
2. You check existing open and recently merged pull requests to make sure
   someone else hasn't addressed the problem already.
3. You open an issue to discuss any significant work — we would hate for your
   time to be wasted.

To send us a pull request, please:

1. Fork the repository.
2. Modify the source, focusing on the specific change you are contributing.
   Reformatting unrelated code makes a change hard to review.
3. Ensure the test suites pass:
   ```bash
   python3 -m pytest tests/ -q
   cd infrastructure/cdk && npx jest && npx cdk synth --quiet
   ```
4. Commit using clear commit messages.
5. Send us a pull request, answering any default questions in the pull request
   interface.

### A note on determinism

This project has one rule that governs most of its design: **the model reads,
Python decides.** A change that moves a number, an integration verdict, or a
citation URL from deterministic code into model output will be declined, even
if it passes the tests. If you are unsure whether a change crosses that line,
open an issue first.

## Finding contributions to work on

Looking at the existing issues is a great way to find something to contribute
on. Issues labelled 'help wanted' or 'good first issue' are a good place to start.

## Code of Conduct

This project has adopted a Code of Conduct. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Security issue notifications

If you discover a potential security issue in this project, please follow the
process in [SECURITY.md](SECURITY.md). Please do **not** create a public GitHub issue.

## Licensing

See the [LICENSE](LICENSE) file for this project's licensing. We will ask you to
confirm the licensing of your contribution.
