# ModulePathList

A simple plugin to list modules with their paths.

## Usage

Run the command `ModulePathList` and switch to the reference view to see a list of all loaded modules and their paths.

Run the command `ModulePathListExports` to see a list of all exported symbols. Same as the default symbols tab, except doesn't show decorated names. Beware as the undecorated names are not canonical (x64dbg sdk thing).

Run the command `ModulePathListImports` to see a list of all imported symbols along with their import address (address of IAT entry), and final module and symbol names (works with forwarded symbols as well)
