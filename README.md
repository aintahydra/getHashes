# getHashes
Obtain (SHA256, MD5, SHA1) hash values of files under a given diretory

# How to run
- Get hash values of Windows PE executables under a certain directory:
`$ python3 <this program> --dir <some dir to scan> -o <outfile name> --winex`
- Get hash values of Windows PE executables and also Linux ELF files:
`$ python3 <this program> --xinex -r --dir <some dir to scan> -o <outfile name>`
- Get hash values of all files under a directory
`$ python3 <this program> --dir <some dir to scan> -o <outfile name>`

# Furthermore
The result can be checked by askVT(https://github.com/aintahydra/askVT)
