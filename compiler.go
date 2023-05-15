go build -ldflags="-H windowsgui -X 'main.manifestFile=memdump.exe.manifest' -linkmode internal" -o memdump.exe .\memdump.go
