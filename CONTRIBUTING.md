# Contribute to goe2ee

- [Introduction](#introduction)
- [FAQ](#faq)
- [How can I contribute?](#how-can-i-contribute)
- [Communication](#communication)
- [Contribute examples](#contribute-examples)
- [Contribute code](#contribute-code)
- [Disclosing vulnerabilities](#disclosing-vulnerabilities)
- [Code style](#code-style)
  - [Working with forks](#working-with-forks)
- [Conduct](#conduct)

## Introduction

_Please note_: We take security and our users' trust very seriously. If you
believe you have found a security issue in goe2ee, please disclose it by
contacting us at cadastros@rafael.net.br.

There are many ways in which you can contribute. The goal of this document is to
provide a high-level overview of how you can get involved in goe2ee.

As a potential contributor, your changes and ideas are welcome at any hour of
the day or night, on weekdays, weekends, and holidays. Please do not ever
hesitate to ask a question or send a pull request.

If you are unsure, just ask or submit the issue or pull request anyways. You
won't be yelled at for giving it your best effort. The worst that can happen is
that you'll be politely asked to change something. We appreciate any sort of
contributions and don't want a wall of rules to get in the way of that.

That said, if you want to ensure that a pull request is likely to be merged,
talk to us! You can find out our thoughts and ensure that your contribution
won't clash with goe2ee direction. A great way to do this is via
[goe2ee Discussions](https://github.com/rafaeljusto/goe2ee/discussions).

## FAQ

- I am new to the community. Where can I find the
  [goe2ee Code of Conduct?](https://github.com/rafaeljusto/goe2ee/blob/main/CODE_OF_CONDUCT.md)

- I have a question. Where can I get
  [answers to questions regarding goe2ee?](#communication)

- I would like to contribute but I am not sure how. Are there
  [easy ways to contribute?](#how-can-i-contribute)
  [Or good first issues?](https://github.com/search?l=&o=desc&q=label%3A%22help+wanted%22+label%3A%22good+first+issue%22+is%3Aopen+repo%3Arafaeljusto%2Fgoe2ee+&s=updated&type=Issues)

- I want to talk to other goe2ee users.
  [How can I become a part of the community?](#communication)

## How can I contribute?

If you want to start to contribute code right away, take a look at the
[list of good first issues](https://github.com/rafaeljusto/goe2ee/labels/good%20first%20issue).

There are many other ways you can contribute. Here are a few things you can do
to help out:

- **Give us a star.** It may not seem like much, but it really makes a
  difference. This is something that everyone can do to help out goe2ee.
  Github stars help the project gain visibility and stand out.

- **Join the community.** Sometimes helping people can be as easy as listening
  to their problems and offering a different perspective. Have a look at
  discussions in the forum and take part in community events. More info on this
  in [Communication](#communication).

- **Answer discussions.** At all times, there are several unanswered discussions
  on GitHub. You can see an
  [overview here](https://github.com/discussions?discussions_q=is%3Aunanswered+org%3Arafaeljusto+sort%3Aupdated-desc).
  If you think you know an answer or can provide some information that might
  help, please share it! Bonus: You get GitHub achievements for answered
  discussions.

- **Help with open issues.** We have a lot of open issues for goe2ee and
  some of them may lack necessary information, some are duplicates of older
  issues. You can help out by guiding people through the process of filling out
  the issue template, asking for clarifying information or pointing them to
  existing issues that match their description of the problem.

- **Review documentation changes.** Most documentation just needs a review for
  proper spelling and grammar. If you think a document can be improved in any
  way, feel free to hit the `edit` button at the top of the page. More info on
  contributing to the documentation [here](#contribute-documentation).

- **Help with tests.** Pull requests may lack proper tests or test plans. These
  are needed for the change to be implemented safely.

## Communication

Check out [goe2ee Discussions](https://github.com/rafaeljusto/goe2ee/discussions).
This is a great place for in-depth discussions and lots of code examples, logs
and similar data.

## Contribute examples

One of the most impactful ways to contribute is by adding examples. You can find
an overview of examples using goe2ee on the
[godocs](https://pkg.go.dev/github.com/rafaeljusto/goe2ee).

_If you would like to contribute a new example, we would love to hear from you!_

Please [open an issue](https://github.com/rafaeljusto/goe2ee/issues/new/choose) to
describe your example before you start working on it. We would love to provide
guidance to make for a pleasant contribution experience. Go through this
checklist to contribute an example:

1. Create a GitHub issue proposing a new example and make sure it's different
   from an existing one.
2. Fork the repo and create a feature branch off of `main` so that changes do
   not get mixed up.
3. Add a descriptive prefix to commits. This ensures a uniform commit history
   and helps structure the changelog.
4. Open a pull request and maintainers will review and merge your example.

## Contribute code

Unless you are fixing a known bug, we **strongly** recommend discussing it with
the core team via a GitHub issue before getting started to ensure your work is
consistent with goe2ee roadmap and architecture.

All contributions are made via pull requests. To make a pull request, you will
need a GitHub account; if you are unclear on this process, see GitHub's
documentation on [forking](https://help.github.com/articles/fork-a-repo) and
[pull requests](https://help.github.com/articles/using-pull-requests). Pull
requests should be targeted at the `main` branch. Before creating a pull
request, go through this checklist:

1. Create a feature branch off of `main` so that changes do not get mixed up.
2. [Rebase](http://git-scm.com/book/en/Git-Branching-Rebasing) your local
   changes against the `main` branch.
3. Run the full project test suite with the `go test ./...` (or equivalent)
   command and confirm that it passes.
4. Run the linters with the `golangci-lint run ./...`
5. Add a descriptive prefix to commits. This ensures a uniform commit history
   and helps structure the changelog.

If a pull request is not ready to be reviewed yet
[it should be marked as a "Draft"](https://docs.github.com/en/github/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/changing-the-stage-of-a-pull-request).

When pull requests fail the automated testing stages (for example unit or E2E
tests), authors are expected to update their pull requests to address the
failures until the tests pass.

Pull requests eligible for review

1. follow the repository's code formatting conventions;
2. include tests that prove that the change works as intended and does not add
   regressions;
3. document the changes in the code and/or the project's documentation;
4. pass the CI pipeline;
5. include a proper git commit message following the
   [Conventional Commit Specification](https://www.conventionalcommits.org/en/v1.0.0/).

If all of these items are checked, the pull request is ready to be reviewed and
you should change the status to "Ready for review" and
[request review from a maintainer](https://docs.github.com/en/github/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/requesting-a-pull-request-review).

Reviewers will approve the pull request once they are satisfied with the patch.

Some other important notes when contributing:
* Please try to minimize the number of dependencies, the goe2ee attempts to work
  only with the Go standard library;
* Only expose types and function that are really required. You can always
  organize better the code in the `internal` package;
* Follow the [robustness principle](https://en.wikipedia.org/wiki/Robustness_principle), be
  conservative in what you do, be liberal in what you accept from others;
* Existing benchmarks should help on verifying the performance impact of your
  code changes, and guide you on tunning for the best solution.

## Disclosing vulnerabilities

Please disclose vulnerabilities exclusively to
[cadastros@rafael.net.br](mailto:cadastros@rafael.net.br). Do not use GitHub issues.

## Code style

Please run `gofmt` to format all source code following the goe2ee standard.

### Working with forks

```bash
# First you clone the original repository
git clone git@github.com:rafaeljusto/goe2ee.git

# Next you add a git remote that is your fork:
git remote add fork git@github.com:<YOUR-GITHUB-USERNAME-HERE>/rafaeljusto/goe2ee.git

# Next you fetch the latest changes from origin for main:
git fetch origin
git checkout main
git pull --rebase

# Next you create a new feature branch off of main:
git checkout my-feature-branch

# Now you do your work and commit your changes:
git add -A
git commit -a -m "fix: this is the subject line" -m "This is the body line. Closes #123"

# And the last step is pushing this to your fork
git push -u fork my-feature-branch
```

Now go to the project's GitHub Pull Request page and click "New pull request"

## Conduct

Whether you are a regular contributor or a newcomer, we care about making this
community a safe place for you and we've got your back.

[goe2ee Community Code of Conduct](https://github.com/rafaeljusto/goe2ee/blob/main/CODE_OF_CONDUCT.md)

We welcome discussion about creating a welcoming, safe, and productive
environment for the community. If you have any questions, feedback, or concerns
[please let us know](#communication).