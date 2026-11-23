# Generated C source — do not edit by hand

`ramzara.c` is the single-file C output of `capi/ramzara_c.v`, generated
with the same flags as the C-lib release build:

```sh
v -Wimpure-v -enable-globals -shared -o c/generated/ramzara.c capi/ramzara_c.v
```

It is refreshed automatically by the `C generated source` workflow on
every push to `master` that touches V sources or the C API files, and
committed back with `[skip ci]`. To regenerate locally, install the
package into `~/.vmodules/metif12/ramzara` first (see CONTRIBUTING.md),
then run the command above from that directory with `-o` pointing back
at this folder.
