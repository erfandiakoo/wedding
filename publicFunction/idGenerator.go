package publicFunction

import (
	"crypto/rand"
	"errors"
	"hash/fnv"
	"log"
	"math"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	TotalBits               = 64
	EpochBits               = 42
	NodeIdBits              = 12
	SequenceBits            = 10
	TimespanShiftBits       = TotalBits - EpochBits
	NodeIdShiftBits         = TotalBits - EpochBits - NodeIdBits
	MacBitsCountInNodId     = NodeIdBits / 2
	RandomBitsCountInNodeId = NodeIdBits / 2

	_lastTimestamp = int64(-1)
	_sequence      = int64(0)
)

var (
	MaxNodeId   = int64(math.Pow(2, NodeIdBits) - 1)
	MaxSequence = int64(math.Pow(2, SequenceBits) - 1)
	CustomEpoch = time.Date(2019, 12, 06, 00, 00, 00, 00, time.UTC).Unix()
	_nodeId     int64
	_lock       interface{} = new(interface{})
)

var IdGenerator *Node

func init() {
	var err error
	IdGenerator, err = NewNode()
	if err != nil {
		log.Fatalln(err)
	}
}

func NewIdGenerator() *Node {
	if IdGenerator == nil {
		var err error
		IdGenerator, err = NewNode()
		if err != nil {
			log.Fatalln(err)
		}
	}
	return IdGenerator
}

var (
	// Epoch is set to the twitter snowflake epoch of Nov 04 2010 01:42:54 UTC in milliseconds
	// You may customize this to set a different epoch for your application.
	Epoch int64 = time.Date(2019, 12, 06, 00, 00, 00, 00, time.UTC).Unix()

	// NodeBits holds the number of bits to use for Node
	// Remember, you have a total 22 bits to share between Node/Step
	NodeBits uint8 = 12

	// StepBits holds the number of bits to use for Step
	// Remember, you have a total 22 bits to share between Node/Step
	StepBits uint8 = 10

	// DEPRECATED: the below four variables will be removed in a future release.
	mu        sync.Mutex
	nodeMax   int64 = -1 ^ (-1 << NodeBits)
	nodeMask        = nodeMax << StepBits
	stepMask  int64 = -1 ^ (-1 << StepBits)
	timeShift       = totalBits - EpochBits
	nodeShift       = totalBits - EpochBits - NodeIdBits

	totalBits int64 = 64
)
var (
	_randomBits  int64
	_maxMacId    int64
	_maxRandomId int64
	_maxNodeId   int64
)

type Node struct {
	mu    sync.Mutex
	epoch time.Time
	time  int64
	node  int64
	step  int64

	nodeMax   int64
	nodeMask  int64
	stepMask  int64
	timeShift uint8
	nodeShift uint8
}

type ID int64

func NewNode() (*Node, error) {

	// re-calc in case custom NodeBits or StepBits were set
	// DEPRECATED: the below block will be removed in a future release.
	mu.Lock()
	nodeMax = -1 ^ (-1 << NodeBits)
	nodeMask = nodeMax << StepBits
	stepMask = -1 ^ (-1 << StepBits)
	timeShift = totalBits - EpochBits
	nodeShift = totalBits - EpochBits - NodeIdBits
	mu.Unlock()

	var n = &Node{}
	n.node = Get()
	n.nodeMax = -1 ^ (-1 << NodeBits)
	n.nodeMask = n.nodeMax << StepBits
	n.stepMask = -1 ^ (-1 << StepBits)
	n.timeShift = NodeBits + StepBits
	n.nodeShift = StepBits

	if n.node < 0 || n.node > n.nodeMax {
		return nil, errors.New("Node number must be between 0 and " + strconv.FormatInt(n.nodeMax, 10))
	}

	var curTime = time.Now()
	// add time.Duration to curTime to make sure we use the monotonic clock if available
	n.epoch = curTime.Add(time.Unix(Epoch/1000, (Epoch%1000)*1000000).Sub(curTime))
	return n, nil
}

// Generate creates and returns a unique snowflake ID
// To help guarantee uniqueness
// - Make sure your system is keeping accurate system time
// - Make sure you never have multiple nodes running with the same node ID
func (n *Node) Generate() ID {

	n.mu.Lock()

	now := time.Since(n.epoch).Nanoseconds() / 1000000

	if now == n.time {
		n.step = (n.step + 1) & n.stepMask

		if n.step == 0 {
			for now <= n.time {
				now = time.Since(n.epoch).Nanoseconds() / 1000000
			}
		}
	} else {
		n.step = 0
	}

	n.time = now

	r := ID((now)<<n.timeShift |
		(n.node << n.nodeShift) |
		(n.step),
	)

	n.mu.Unlock()
	return r
}

// Int64 returns an int64 of the snowflake ID
func (f ID) Int64() int64 {
	return int64(f)
}

func Get() int64 {
	macId := getMacId()
	randomId := getRandomId()
	nodeId := macId << _randomBits
	nodeId |= randomId
	nodeId = nodeId & _maxNodeId

	return nodeId
}
func getHashCode(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

func getMacId() int64 {
	var macValue = getMacValue()
	var macHash = getHashCode(macValue)
	var macInt = int64(macHash) & _maxMacId

	return macInt
}

func getMacValue() string {
	var macValue string
	var networkInterfaces, err = net.Interfaces()
	if err != nil {
		log.Println(err)
		return ""
	}
	for _, networkInterface := range networkInterfaces {
		macValue = macValue + networkInterface.HardwareAddr.String()
	}
	return macValue
}

func getRandomId() int64 {
	provider, err := rand.Int(rand.Reader, big.NewInt(128))
	if err != nil {
		log.Println(err)
		return 0
	}
	unodeId := uint32(provider.Int64())
	var shiftedUnodeId = unodeId >> (32 - _randomBits)
	var randInt = int64(shiftedUnodeId) & _maxRandomId
	return randInt
}
func (f ID) Node() int64 {
	return int64(f) & nodeMask >> nodeShift
}
