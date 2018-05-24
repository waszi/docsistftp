# docsistftp
Docsis TFTP Server

Features:
- dynamic DOCSIS TLV config generator
- SQL support (postgres/mysql/sqlite)
- Embedded scripting [Anko](https://github.com/mattn/anko)
- automatic CVC Certificate extraction from firmware files
- clean "URLs" (/cm.anko?mac=11:22:33:44:55&model=EPC3949 -> /cm/EPC3949/11:22:33:44:55)

TODO:
- documentation
- better error handling
- better logging
- support plain text files (pxelinux/ipxe/non DOCSIS devices)
- prometheus metrics
- golang templates support
- ~~chroot()/setuid() - not important at the moment, internally will use docker~~
- ~~Dockerfile (soon)~~
- publish docker images
