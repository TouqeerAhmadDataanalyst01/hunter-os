# Local Plugin Archives

This directory is for plugin ZIP files you have manually obtained and are authorized to inspect. The scanner does not download files or make network requests.

For the `file-manager` target, manually download:

`https://downloads.wordpress.org/plugin/file-manager.zip`

Save it as `targets/archives/file-manager.zip`, then run `python main.py --target file-manager` from the repository root. The ZIP is extracted under `/tmp/plugins/file-manager/` before local source inspection.