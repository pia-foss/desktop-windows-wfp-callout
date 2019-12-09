# windows-wfp-callout

This repository contains the WFP callout driver used by PIA Desktop on Windows, currently used for the app exclusions / split tunnel feature.

# Building

* Install the EWDK (to `C:\EWDK\<version>` to be detected automatically).
* Set code signing variables - `PIA_SIGN_SHA256_CERT`, `PIA_SIGN_SHA1_CERT`, `PIA_SIGN_CROSSCERT`, `PIA_SIGN_TIMESTAMP`.  See `build.bat --help`.  An EV certificate is required for the driver to be installable.  It can be built without signing, but the build will not be installable.
* Build with `build.bat` from a command prompt.  (You do not need to open a "developer command prompt", build.bat locates the EWDK and sets up the environment.)

Artifacts will be produced in `dist\Release-x86` and `dist\Release-x64`.

See `build.bat --help` for more options and environment variables.
