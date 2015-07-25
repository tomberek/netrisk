Download `stack` from [here](https://github.com/commercialhaskell/stack/wiki/Downloads) for your particular architecture.

From inside a folder with unzipped contents `tar zxvf netrisk-X.X.X.X.tar.gz`; `stack setup` should install appropriate GHC and setup the build environment.

`stack install` will build and install the executable to a default location for binaries. Run with `netrisk testdata.txt`

`stack tests` to run tests.
