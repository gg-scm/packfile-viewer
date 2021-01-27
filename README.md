# gg Packfile Viewer

[![Contributor Covenant](https://img.shields.io/badge/Contributor%20Covenant-v2.0%20adopted-ff69b4.svg)](CODE_OF_CONDUCT.md)

packfile-viewer is a demo application for the [`gg-scm.io/pkg/git/packfile`][]
package. It allows you to fetch Git repositories and inspect their contents
interactively, similar to [GitWeb][], but with more debugging details.

[`gg-scm.io/pkg/git/packfile`]: https://pkg.go.dev/gg-scm.io/pkg/git/packfile
[GitWeb]: https://git-scm.com/book/en/v2/Git-on-the-Server-GitWeb

## Getting Started

packfile-viewer is built using [`yb`][]. Once you've installed `yb`, you can
build the tool with:

```shell
yb build
```

And once that has finished, you can run the server locally with:

```shell
yb exec
```

The server will then be available at `http://localhost:8080/`.

[`yb`]: https://github.com/yourbase/yb

## License

[Apache 2.0](LICENSE)
