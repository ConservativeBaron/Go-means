package main

import (
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Point struct {
	x float64
	y float64
}

type KMeans struct {
	k             int
	data          []Point
	centroids     []Point
	clusters      [][]Point
	maxIterations int
}

func NewKMeans(k int, data []Point) *KMeans {
	return &KMeans{
		k:             k,
		data:          data,
		centroids:     make([]Point, k),
		clusters:      make([][]Point, k),
		maxIterations: 100,
	}
}

func (kmeans *KMeans) run() [][]Point {
	// initialize centroids
	for i := 0; i < kmeans.k; i++ {
		kmeans.centroids[i] = kmeans.data[i]
	}

	for iteration := 0; iteration < kmeans.maxIterations; iteration++ {
		// reset clusters
		for i := 0; i < kmeans.k; i++ {
			kmeans.clusters[i] = []Point{}
		}

		// assign point to nearest cluster
		for _, point := range kmeans.data {
			distances := make([]float64, kmeans.k)
			for i := 0; i < kmeans.k; i++ {
				distances[i] = euclideanDistance(point, kmeans.centroids[i])
			}
			nearestCentroidIndex := minIndex(distances)
			kmeans.clusters[nearestCentroidIndex] = append(kmeans.clusters[nearestCentroidIndex], point)
		}

		// update centroids based off of means
		for i, cluster := range kmeans.clusters {
			if len(cluster) > 0 {
				kmeans.centroids[i] = computeCentroid(cluster)
			}
		}
	}

	return kmeans.clusters
}

func euclideanDistance(point1 Point, point2 Point) float64 {
	return math.Sqrt(math.Pow(point1.x-point2.x, 2) + math.Pow(point1.y-point2.y, 2))
}

func computeCentroid(cluster []Point) Point {
	numPoints := len(cluster)
	if numPoints == 1 {
		return cluster[0]
	}
	sumX, sumY := 0.0, 0.0
	for _, point := range cluster {
		sumX += point.x
		sumY += point.y
	}
	return Point{x: sumX / float64(numPoints), y: sumY / float64(numPoints)}
}

func minIndex(slice []float64) int {
	min := slice[0]
	minIndex := 0
	for i, value := range slice {
		if value < min {
			min = value
			minIndex = i
		}
	}
	return minIndex
}

func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

func main() {
	// check if enough arguments are passed
	if len(os.Args) < 2 {
		log.Fatal("Please provide a path to a pcap file as an argument.")
	}

	// open the pcap file
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// filter pcap
	handle, err := pcap.OpenOffline(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer handle.Close()
	filter := "ip"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		panic(err)
	}

	// extract the source IP addresses
	var data []Point
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	seenIPs := make(map[string]bool)
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)
		ipStr := ip.SrcIP.String()
		if seenIPs[ipStr] {
			continue
		}
		seenIPs[ipStr] = true
		packetLength := float64(len(packet.Data()))
		point := Point{x: float64(IP4toInt(ip.SrcIP)), y: packetLength}
		data = append(data, point)
	}

	// execute k-means clustering
	kmeans := NewKMeans(2, data)
	clusters := kmeans.run()

	// print clustered IP addresses
	for _, cluster := range clusters {
		for _, point := range cluster {
			intIP := int64(point.x)
			normalIP := net.IPv4(byte(intIP>>24), byte(intIP>>16), byte(intIP>>8), byte(intIP))
			fmt.Println(normalIP)
			//fmt.Printf("[%s, %d] \n", normalIP.String(), int(point.y))
		}
	}
}
