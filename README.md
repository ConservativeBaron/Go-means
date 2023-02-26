
<br />
<div align="center">
  <a href="https://github.com/ConservativeBaron/Go-means">
    <img src="https://github.com/ConservativeBaron/Go-means/raw/main/Images/Funny-blue-squirrel.png" alt="Logo">
  </a>

  <h3 align="center">Go-Means</h3>

  <p align="center">
    A simple k-means algorithm in golang
    <br />
</a>
    <br />
    <br />
    <a href="https://unhittable.pw">Keragation</a>
    ·
    <a href="https://discord.gg/mitigation">Discord</a>
  </p>
</div>

# Installing go-lang
### Ubuntu / Debian:
single command:
```sh
sudo apt update && sudo apt install golang -y
```

* Update your system `sudo apt update`
* Install golang using apt `sudo apt install golang -y`
* Verify installation `go version`

# Installing go-means
## Ubuntu / Debian:
single command:

```sh
git clone https://github.com/ConservativeBaron/Go-means && cd Go-means/src && go get -u github.com/google/gopacket/pcap
```

* Use the git package manager `git clone https://github.com/ConservativeBaron/Go-means`
* CD into the directory `cd Go-means/src`
* Go get gopacket `go get -u github.com/google/gopacket/pcap`
* Build the file `go build kmeans-clustering.go`
* Finally, run the binary `./kmeans-clustering capture.pcap`

## Windows
single command:

```sh
git clone https://github.com/ConservativeBaron/Go-means && cd Go-means/src && go get -u github.com/google/gopacket/pcap
```

* Use the git package manager git clone https://github.com/ConservativeBaron/Go-means
* CD into the directory cd Go-means/src
* Go get gopacket go get -u github.com/google/gopacket/pcap
* Build the file go build kmeans-clustering.go
* Finally, run the binary .\kmeans-clustering.exe capture.pcap

# Examples
<img src="https://raw.githubusercontent.com/ConservativeBaron/Go-means/main/Images/example_1.png" alt="Example usage #1, aarm64">

# Built With
[![Go][golang-svg]][golang-url]

[golang-svg]: https://img.shields.io/badge/Go-1.16-blue.svg
[golang-url]: https://golang.org/

