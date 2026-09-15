package l1

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"sync"
	"time"

	"ipvn7/pkg/l0"
)

// RouterProfile define el perfil topológico del nodo según su hardware y función de red
type RouterProfile string

const (
	ProfileMicro    RouterProfile = "micro"    // IoT / Móvil / Edge (8 anillos, 64 pares)
	ProfileStandard RouterProfile = "standard" // Desktop / Laptop / Servidor estándar (16 anillos, 256 pares)
	ProfileBackbone RouterProfile = "backbone" // Gateway / Anchor / Servidor dedicado (32 anillos, 1024 pares)
	ProfileCustom   RouterProfile = "custom"   // Parámetros N-anillos configurables ad-hoc
)

// Constantes canónicas y valores por defecto (compatibilidad hacia atrás)
const (
	DefaultNumRings     = 16
	DefaultPeersPerRing = 16
	DefaultMaxPeers     = DefaultNumRings * DefaultPeersPerRing // 256 pares por defecto
	NumRings            = DefaultNumRings                       // Retrocompatibilidad con código existente
	PeersPerRing        = DefaultPeersPerRing
	MaxPeers            = DefaultMaxPeers
)

// RouterConfig define el dimensionamiento elástico y las heurísticas de enrutamiento
type RouterConfig struct {
	Profile            RouterProfile `json:"profile"`
	NumRings           int           `json:"num_rings"`             // N anillos logarítmicos (4 a 64)
	PeersPerRing       int           `json:"peers_per_ring"`        // Capacidad acotada por anillo
	MaxTotalPeers      int           `json:"max_total_peers"`       // Capacidad total de memoria
	AlphaLatencyWeight float64       `json:"alpha_latency_weight"`  // Ponderación de latencia RTT (0.0=XOR puro, 0.35=híbrido 2D)
	AutoRebalance      bool          `json:"auto_rebalance"`        // Prospección periódica de anillos vacíos
}

// DefaultRouterConfig retorna la configuración estándar optimizada (16 anillos, 256 pares)
func DefaultRouterConfig() RouterConfig {
	return RouterConfig{
		Profile:            ProfileStandard,
		NumRings:           DefaultNumRings,
		PeersPerRing:       DefaultPeersPerRing,
		MaxTotalPeers:      DefaultMaxPeers,
		AlphaLatencyWeight: 0.35,
		AutoRebalance:      true,
	}
}

// MicroRouterConfig retorna la configuración liviana para IoT o dispositivos móviles (8 anillos, 64 pares)
func MicroRouterConfig() RouterConfig {
	return RouterConfig{
		Profile:            ProfileMicro,
		NumRings:           8,
		PeersPerRing:       8,
		MaxTotalPeers:      64,
		AlphaLatencyWeight: 0.25,
		AutoRebalance:      false,
	}
}

// BackboneRouterConfig retorna la configuración de alto rendimiento para Gateways y Anclas (32 anillos, 1024 pares)
func BackboneRouterConfig() RouterConfig {
	return RouterConfig{
		Profile:            ProfileBackbone,
		NumRings:           32,
		PeersPerRing:       32,
		MaxTotalPeers:      1024,
		AlphaLatencyWeight: 0.40,
		AutoRebalance:      true,
	}
}

// Estados de la Máquina de Estados Finitos (FSM) de salud de pares
const (
	HealthStateHealthy     = 0 // Flujo óptimo y pacing respetado
	HealthStateDegraded    = 1 // Incremento de RTT o ligera varianza de Jitter
	HealthStateUnstable    = 2 // Pérdida moderada de paquetes; activa Make-Before-Break
	HealthStateUnreachable = 3 // Ausencia total de ACKs o pérdida crítica
	HealthStateQuarantined = 4 // Anomalía maliciosa o aislamiento de vecindario
)

// PeerLocator representa la dirección física efímera de un par
type PeerLocator struct {
	PhysicalAddr *net.UDPAddr
	LastSeen     time.Time
	LatencyMs    float64
}

// PeerNode representa un par en la red en malla
type PeerNode struct {
	DID             string
	PublicKey       ed25519.PublicKey
	Locator         PeerLocator
	RingIndex       int
	HealthState     int
	JitterMs        float64
	LossRate        float64
	HealthScore     float64
	QuarantineUntil time.Time
}

// KleinbergRouter implementa el enrutamiento geométrico elástico de Mundo Pequeño
type KleinbergRouter struct {
	mu          sync.RWMutex
	LocalDID    string
	LocalPub    ed25519.PublicKey
	config      RouterConfig
	rings       [][]*PeerNode
	peerIndex   map[string]*PeerNode
	TotalRoutes int
}

// NewKleinbergRouterWithConfig inicializa el enrutador con configuración elástica explícita
func NewKleinbergRouterWithConfig(localID *l0.Identity, cfg RouterConfig) *KleinbergRouter {
	if cfg.NumRings <= 0 {
		cfg.NumRings = DefaultNumRings
	}
	if cfg.PeersPerRing <= 0 {
		cfg.PeersPerRing = DefaultPeersPerRing
	}
	if cfg.MaxTotalPeers <= 0 {
		cfg.MaxTotalPeers = cfg.NumRings * cfg.PeersPerRing
	}
	if cfg.AlphaLatencyWeight < 0.0 || cfg.AlphaLatencyWeight > 1.0 {
		cfg.AlphaLatencyWeight = 0.35
	}

	rings := make([][]*PeerNode, cfg.NumRings)
	for i := 0; i < cfg.NumRings; i++ {
		rings[i] = make([]*PeerNode, 0, cfg.PeersPerRing)
	}

	return &KleinbergRouter{
		LocalDID:  localID.DID(),
		LocalPub:  localID.PublicKey,
		config:    cfg,
		rings:     rings,
		peerIndex: make(map[string]*PeerNode),
	}
}

// NewKleinbergRouter inicializa el enrutador con la configuración estándar (16 anillos, 256 pares)
func NewKleinbergRouter(localID *l0.Identity) *KleinbergRouter {
	return NewKleinbergRouterWithConfig(localID, DefaultRouterConfig())
}

// GetConfig retorna la configuración activa del enrutador
func (r *KleinbergRouter) GetConfig() RouterConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.config
}

// XORKeyDistanceN calcula la distancia XOR de 256 bits y determina el anillo logarítmico (0 a numRings-1)
func XORKeyDistanceN(keyA, keyB []byte, numRings int) int {
	if numRings <= 0 {
		numRings = DefaultNumRings
	}
	if len(keyA) != 32 || len(keyB) != 32 {
		return numRings - 1
	}

	// Contar ceros iniciales en XOR (Leading Zeros)
	lz := 0
	for i := 0; i < 4; i++ {
		chunkA := binary.BigEndian.Uint64(keyA[i*8 : (i+1)*8])
		chunkB := binary.BigEndian.Uint64(keyB[i*8 : (i+1)*8])
		xor := chunkA ^ chunkB
		if xor == 0 {
			lz += 64
		} else {
			lz += bits.LeadingZeros64(xor)
			break
		}
	}

	// Mapear los 256 bits a numRings anillos logarítmicos
	// Mayor cantidad de ceros iniciales = nodos más cercanos = Anillo 0
	bitsPerRing := 256 / numRings
	if bitsPerRing <= 0 {
		bitsPerRing = 1
	}
	ring := (256 - lz) / bitsPerRing
	if ring >= numRings {
		ring = numRings - 1
	}
	if ring < 0 {
		ring = 0
	}
	return ring
}

// XORKeyDistance calcula la distancia logarítmica usando la cantidad de anillos por defecto
func XORKeyDistance(keyA, keyB []byte) int {
	return XORKeyDistanceN(keyA, keyB, DefaultNumRings)
}

// AddOrUpdatePeer inserta o actualiza un par con política de desalojo inteligente (Smart Eviction)
func (r *KleinbergRouter) AddOrUpdatePeer(did string, addr *net.UDPAddr, latencyMs float64) error {
	pub, err := l0.PublicKeyFromDID(did)
	if err != nil {
		return fmt.Errorf("did inválido: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 1. Si el par ya existe, actualizamos su localizador (IP Roaming sin caída)
	if existing, found := r.peerIndex[did]; found {
		existing.Locator.PhysicalAddr = addr
		existing.Locator.LastSeen = time.Now()
		existing.Locator.LatencyMs = latencyMs
		return nil
	}

	ring := XORKeyDistanceN(r.LocalPub, pub, r.config.NumRings)

	// 2. Si el anillo específico está lleno, aplicar política de desalojo local
	if len(r.rings[ring]) >= r.config.PeersPerRing {
		evictIdx := -1

		// Prioridad 1: Desalojar nodos en Cuarentena o Inaccesibles
		for i, p := range r.rings[ring] {
			if p.HealthState == HealthStateQuarantined || p.HealthState == HealthStateUnreachable {
				evictIdx = i
				break
			}
		}

		// Prioridad 2: Desalojar nodos inestables con degradación severa
		if evictIdx == -1 {
			for i, p := range r.rings[ring] {
				if p.HealthState == HealthStateUnstable {
					evictIdx = i
					break
				}
			}
		}

		// Prioridad 3: Reemplazo competitivo si el nuevo par ofrece mejor latencia que el peor del anillo
		if evictIdx == -1 {
			worstIdx := 0
			worstLatency := r.rings[ring][0].Locator.LatencyMs
			for i, p := range r.rings[ring] {
				if p.Locator.LatencyMs > worstLatency {
					worstLatency = p.Locator.LatencyMs
					worstIdx = i
				}
			}
			if latencyMs < worstLatency {
				evictIdx = worstIdx
			}
		}

		if evictIdx >= 0 {
			oldPeer := r.rings[ring][evictIdx]
			delete(r.peerIndex, oldPeer.DID)

			newPeer := &PeerNode{
				DID:       did,
				PublicKey: pub,
				Locator: PeerLocator{
					PhysicalAddr: addr,
					LastSeen:     time.Now(),
					LatencyMs:    latencyMs,
				},
				RingIndex:   ring,
				HealthState: HealthStateHealthy,
				HealthScore: 100.0,
			}
			r.rings[ring][evictIdx] = newPeer
			r.peerIndex[did] = newPeer
		}
		return nil
	}

	// 3. Si la capacidad global está al límite, desalojar el par globalmente más deteriorado
	if len(r.peerIndex) >= r.config.MaxTotalPeers {
		globalWorstDID := ""
		globalWorstRing := -1
		globalWorstIdx := -1
		worstScore := 999.0

		for rIdx, ringList := range r.rings {
			if len(ringList) <= 1 {
				continue // No vaciar anillos únicos para no fragmentar el árbol de enrutamiento
			}
			for pIdx, p := range ringList {
				score := p.HealthScore - (p.Locator.LatencyMs / 10.0)
				if score < worstScore {
					worstScore = score
					globalWorstDID = p.DID
					globalWorstRing = rIdx
					globalWorstIdx = pIdx
				}
			}
		}

		if globalWorstDID != "" && globalWorstRing >= 0 && globalWorstIdx >= 0 {
			delete(r.peerIndex, globalWorstDID)
			// Remover del slice
			r.rings[globalWorstRing] = append(r.rings[globalWorstRing][:globalWorstIdx], r.rings[globalWorstRing][globalWorstIdx+1:]...)
		}
	}

	newPeer := &PeerNode{
		DID:       did,
		PublicKey: pub,
		Locator: PeerLocator{
			PhysicalAddr: addr,
			LastSeen:     time.Now(),
			LatencyMs:    latencyMs,
		},
		RingIndex:   ring,
		HealthState: HealthStateHealthy,
		HealthScore: 100.0,
	}

	r.rings[ring] = append(r.rings[ring], newPeer)
	r.peerIndex[did] = newPeer
	r.TotalRoutes++
	return nil
}

// CalculateHealthScore calcula el puntaje de mérito de 0 a 100 y el estado FSM
func CalculateHealthScore(pacingCompliance, jitterMs, lossRate float64) (float64, int) {
	jitterPen := (jitterMs / 50.0) * 30.0
	if jitterPen > 30.0 {
		jitterPen = 30.0
	}
	lossPen := lossRate * 40.0
	if lossPen > 40.0 {
		lossPen = 40.0
	}

	score := (pacingCompliance * 30.0) + (30.0 - jitterPen) + (40.0 - lossPen)
	if score < 0 {
		score = 0
	} else if score > 100 {
		score = 100
	}

	state := HealthStateHealthy
	if score < 25.0 || lossRate >= 0.4 {
		state = HealthStateUnreachable
	} else if score < 50.0 || lossRate >= 0.20 || jitterMs > 60.0 {
		state = HealthStateUnstable
	} else if score < 75.0 || lossRate >= 0.05 || jitterMs > 25.0 {
		state = HealthStateDegraded
	}
	return score, state
}

// UpdatePeerHealth actualiza las métricas empíricas y transiciona la FSM del par
func (r *KleinbergRouter) UpdatePeerHealth(did string, pacingCompliance, jitterMs, lossRate float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	peer, found := r.peerIndex[did]
	if !found {
		return
	}

	score, state := CalculateHealthScore(pacingCompliance, jitterMs, lossRate)
	peer.JitterMs = jitterMs
	peer.LossRate = lossRate
	peer.HealthScore = score
	peer.HealthState = state
}

// FindNextHop implementa el reenvío voraz hacia la clave destino con métrica híbrida 2D (XOR + EWMA Latency)
// y conmutación proactiva Make-Before-Break
func (r *KleinbergRouter) FindNextHop(destDID string) (*PeerNode, error) {
	pubDest, err := l0.PublicKeyFromDID(destDID)
	if err != nil {
		return nil, fmt.Errorf("did destino inválido: %w", err)
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// 1. Si está en índice directo y saludable, entrega directa inmediata
	if direct, found := r.peerIndex[destDID]; found {
		if direct.HealthState == HealthStateHealthy {
			return direct, nil
		}
	}

	// 2. Búsqueda voraz con función de coste híbrida 2D (distancia XOR logarítmica ponderada con latencia y salud)
	var bestPeer *PeerNode
	bestCost := 999999.0
	numRings := r.config.NumRings
	alpha := r.config.AlphaLatencyWeight

	for _, peer := range r.peerIndex {
		// Descartar pares inaccesibles o en cuarentena
		if peer.HealthState == HealthStateQuarantined || peer.HealthState == HealthStateUnreachable {
			continue
		}

		// Distancia XOR hacia el destino
		distRing := XORKeyDistanceN(peer.PublicKey, pubDest, numRings)
		normalizedXOR := float64(distRing) / float64(numRings)

		// Penalización por latencia física (normalizada a 250ms)
		normLat := peer.Locator.LatencyMs / 250.0
		if normLat > 1.0 {
			normLat = 1.0
		}

		// Bonificación de salud FSM
		healthBonus := (peer.HealthScore / 100.0) * 0.2

		// Función de coste híbrida 2D
		cost := ((1.0 - alpha) * normalizedXOR) + (alpha * normLat) - healthBonus

		if cost < bestCost {
			bestCost = cost
			bestPeer = peer
		}
	}

	// 3. Fallback si no hay candidato por coste: retornar el par más saludable disponible
	if bestPeer == nil {
		for _, peer := range r.peerIndex {
			if bestPeer == nil || peer.HealthScore > bestPeer.HealthScore {
				bestPeer = peer
			}
		}
	}

	if bestPeer == nil {
		return nil, errors.New("no hay rutas disponibles hacia el destino")
	}

	return bestPeer, nil
}

// GetAllPeers retorna una instantánea de todos los pares registrados
func (r *KleinbergRouter) GetAllPeers() []*PeerNode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]*PeerNode, 0, len(r.peerIndex))
	for _, p := range r.peerIndex {
		pCopy := *p
		res = append(res, &pCopy)
	}
	return res
}

// GetRingDistribution entrega la cantidad de pares alojados en cada uno de los N anillos
func (r *KleinbergRouter) GetRingDistribution() []int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	dist := make([]int, len(r.rings))
	for i, ringPeers := range r.rings {
		dist[i] = len(ringPeers)
	}
	return dist
}

// GetRingPeers entrega los pares pertenecientes a un anillo específico
func (r *KleinbergRouter) GetRingPeers(ringIndex int) []*PeerNode {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if ringIndex < 0 || ringIndex >= len(r.rings) {
		return nil
	}

	res := make([]*PeerNode, len(r.rings[ringIndex]))
	copy(res, r.rings[ringIndex])
	return res
}

// RebalanceRings detecta anillos despoblados (huecos topológicos) para prospección proactiva
func (r *KleinbergRouter) RebalanceRings() []int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	starvedRings := make([]int, 0)
	for i, ringPeers := range r.rings {
		if len(ringPeers) == 0 {
			starvedRings = append(starvedRings, i)
		}
	}
	return starvedRings
}

// HandleRoamingUpdate procesa un paquete de roaming y actualiza el localizador
func (r *KleinbergRouter) HandleRoamingUpdate(pkt *l0.Packet, newAddr *net.UDPAddr) error {
	valid, err := pkt.VerifyPacketSignature()
	if err != nil || !valid {
		return errors.New("firma de paquete de roaming inválida")
	}

	return r.AddOrUpdatePeer(pkt.SourceDID, newAddr, 1.1) // 1.1ms benchmark de conmutación
}

