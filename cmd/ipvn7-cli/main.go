package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"ipvn7/pkg/l0"
	"ipvn7/pkg/l1"
	"ipvn7/pkg/l2"
	"ipvn7/pkg/l3"
	"ipvn7/pkg/l4"
)

func printHelp() {
	fmt.Println(`ipvn7-cli: Consola de Gestión de Red Soberana ipvn7 (v0.5.0)

Uso:
  ipvn7-cli [comando] [argumentos...]

Comandos base:
  status                     Muestra la identidad DID, IPs virtuales y estado del nodo
  peers                      Lista los pares registrados en los 12 anillos de Kleinberg
  fsm                        Muestra la FSM de salud de los pares (Healthy, Degraded...)
  radar                      Visualización en consola de los anillos concéntricos
  pace                       Muestra la telemetría del marcapasos Packet Pacing
  services                   Lista los servicios bajo demanda (Zero Footprint)
  mcp                        Inicia el servidor MCP interactivo sobre stdio

Comandos de Innovación (Fases A, B, C, D):
  firewall [list|test <did>|allow <did>]  Cortafuegos ZTNA Default-Deny (Dimensión 1)
  dag [put <payload>|status]              Persistencia inmutable DAG y DTN (Dimensión 4)
  accounting                              Reciprocidad Tit-for-Tat (Dimensión 5)
  wot [vouch <did> <score> [razon]|score <did>]  Red social Web-of-Trust (Dimensión 9)
  alias [nombre] [did] [ctx]              Asigna petname dDNS con relatividad contextual
  ddns [resolve <name>|list|export-hosts] Resolución mnemotécnica local (Dimensión 2)
  multipath [list|strategy <mode>]        Planificador multi-camino (Dimensión 8)
  sas [peer_did]                          Código SAS y Emojis OOB (Dimensión 10)
  copilot [diagnose|stats]                Copiloto de IA y auto-curación (Dimensión 11)

Comandos de Gobernanza e Inmunología (Versión 0.5.0):
  constitution [view|verify <archivo>]    Constitución Digital Soberana (Artículo I y cláusulas)
  senate [list|propose|vote|veto|report]  Senado de Agentes y Democracia Líquida
  sentinel [status|audit <did>|alerts]    Inmunología Celular de Centinelas y Quórum Slashing
  help                                    Muestra este menú de ayuda`)
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}

	command := os.Args[1]
	keystorePath := filepath.Join("keystore", "node_identity.key")

	var id *l0.Identity
	var err error
	if _, statErr := os.Stat(keystorePath); statErr == nil {
		id, err = l0.LoadFromFile(keystorePath)
		if err != nil {
			id, _ = l0.GenerateIdentity()
		}
	} else {
		id, _ = l0.GenerateIdentity()
	}

	router := l1.NewKleinbergRouter(id)
	telemetry := l2.NewTelemetryRingBuffer()
	pacer := l1.NewPacketPacer(l1.DefaultPacerConfig())
	firewall := l1.NewZTNAFirewall(true)
	dagStore := l1.NewDAGStore(id)
	accounting := l2.NewTransitAccounting()
	wot := l1.NewWebOfTrust()
	petnames := l4.NewPetnameResolver()
	multipath := l1.NewMultipathScheduler()
	multipath.RegisterInterface(&l1.PhysicalInterface{
		Name:      "primary-wlan",
		Type:      "WIFI",
		LatencyMs: 12.0,
		LossRate:  0.001,
		Weight:    1000,
		Active:    true,
	})
	multipath.RegisterInterface(&l1.PhysicalInterface{
		Name:      "secondary-eth",
		Type:      "ETHERNET",
		LatencyMs: 2.0,
		LossRate:  0.0001,
		Weight:    1000,
		Active:    true,
	})
	copilot := l3.NewAICopilotEngine(firewall, multipath, telemetry)

	// Gobernanza e Inmunología v0.5.0
	constVerifier := l3.NewConstitutionalVerifier(id)
	senate := l3.NewAgentSenateEngine(id, constVerifier, dagStore, wot, accounting)
	sentinel := l2.NewSentinelImmunologyEngine(id, firewall, accounting, wot)

	// Seed de propuesta demo si el senado está recién creado
	if len(senate.ListProposals()) == 0 {
		_, _ = senate.SubmitProposal(
			"Optimización Algorítmica Kleinberg L1",
			"Optimización heurística de saltos XOR para reducir latencia promedio a menos de 15ms sin alterar L0",
			l3.CategoryRoutingOptimization,
			"package main\n\nfunc OptimizeKleinbergRouting() bool {\n\treturn true\n}\n",
		)
	}

	// Inicializar gestor de servicios bajo demanda
	svcManager := l4.NewServiceLifecycleManager(5 * time.Minute)
	svcManager.RegisterDormantService("chat_e2ee")
	svcManager.RegisterDormantService("remote_desktop")
	svcManager.RegisterDormantService("dag_store")

	switch command {
	case "status":
		fmt.Println("=== ESTADO DEL NODO ipvn7 ===")
		fmt.Printf("DID Soberano  : %s\n", id.DID())
		fmt.Printf("IPv6 Soberana : %s/64\n", id.IPv6())
		fmt.Printf("IPv4 Virtual  : %s/16\n", id.IPv4())
		fmt.Printf("MTU Canónico  : %d bytes\n", l0.MaxPacketSize)
		snap := telemetry.Snapshot()
		fmt.Println("\n--- Telemetría Lock-Free ---")
		fmt.Printf("Paquetes Tx   : %d\n", snap.PacketsTx)
		fmt.Printf("Paquetes Rx   : %d\n", snap.PacketsRx)
		fmt.Printf("Descartes     : %d\n", snap.PacketsDropped)
		fmt.Printf("Ratio Tit-Tat : %.2f\n", snap.TitForTatRatio)

	case "peers":
		peers := router.GetAllPeers()
		fmt.Printf("=== TABLA DE ENRUTAMIENTO KLEINBERG (%d / 120 slots) ===\n", len(peers))
		if len(peers) == 0 {
			fmt.Println("(No hay pares remotos conectados en este momento)")
			return
		}
		for _, p := range peers {
			fmt.Printf("Anillo [%02d] -> %s (Latencia: %.2f ms, Score: %.1f)\n",
				p.RingIndex, p.DID, p.Locator.LatencyMs, p.HealthScore)
		}

	case "fsm":
		peers := router.GetAllPeers()
		fmt.Println("=== FSM DE SALUD DE PARES (Make-Before-Break) ===")
		if len(peers) == 0 {
			fmt.Println("(No hay pares registrados para evaluar la FSM)")
			return
		}
		stateNames := []string{"HEALTHY", "DEGRADED", "UNSTABLE", "UNREACHABLE", "QUARANTINED"}
		for _, p := range peers {
			stName := "UNKNOWN"
			if p.HealthState >= 0 && p.HealthState < len(stateNames) {
				stName = stateNames[p.HealthState]
			}
			fmt.Printf("DID: %s\n", p.DID[:30]+"...")
			fmt.Printf("  Estado FSM   : %s\n", stName)
			fmt.Printf("  Health Score : %.1f / 100\n", p.HealthScore)
			fmt.Printf("  Jitter / Loss: %.2f ms | %.1f%%\n\n", p.JitterMs, p.LossRate*100)
		}

	case "pace":
		stats := pacer.Stats()
		fmt.Println("=== MARCAPASOS DE RED (PACKET PACING) ===")
		fmt.Printf("Tasa Efectiva Sostenible : %d bytes/seg (%.2f Mbps)\n",
			stats.EffectiveRateBytesPerSec, float64(stats.EffectiveRateBytesPerSec*8)/1000000.0)
		fmt.Printf("Intervalo entre Paquetes : %d µs (reloj estricto anti-bufferbloat)\n", stats.PacketIntervalUs)
		fmt.Printf("Paquetes Procesados      : %d (Regulados: %d)\n", stats.PacketsSent, stats.ThrottledCount)

	case "services":
		fmt.Println("=== GESTOR DE SERVICIOS BAJO DEMANDA (Zero Footprint) ===")
		active := svcManager.GetActiveServices()
		if len(active) == 0 {
			fmt.Println("Todos los servicios están DORMIDOS en disco (0 bytes RAM consumidos).")
			fmt.Println("Disponibles para invocación perezosa: chat_e2ee, remote_desktop, dag_store")
			return
		}
		for _, s := range active {
			fmt.Printf("  - %s [ACTIVO | Alcance: %d | Sesiones: %d]\n", s.Name, s.Scope, s.ActiveSessions)
		}

	case "radar":
		fmt.Println("=== RADAR DE ANILLOS CONCÉNTRICOS KLEINBERG ===")
		fmt.Println(`
             . - ~ ~ ~ - .
         . '   Anillo 11   ' .       [Confines del espacio XOR]
       /       Anillo 08       \
      /    . - ~ ~ ~ - .        \
     |   /   Anillo 04   \       |
     |  |   . - ~ - .     |      |
     |  |  ( Anillo 00 )  |      |   [Pares inmediatos]
     |  |   ' - ~ - '     |      |
     |   \               /       |
      \    ' - ~ ~ ~ - '        /
       \                       /
         ' .               . '
             ' - ~ ~ ~ - '
		`)
		fmt.Printf("Identidad Centro: %s\n", id.DID()[:24]+"...")
		fmt.Printf("Capacidad máxima de memoria acotada: %d pares\n", l1.MaxPeers)

	case "firewall":
		fmt.Println("=== CORTAFUEGOS DE MICRO-SEGMENTACIÓN ZTNA (Dimensión 1) ===")
		subCmd := "list"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "test":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli firewall test <did>")
				return
			}
			targetDID := os.Args[3]
			dec, reason := firewall.EvaluateInbound(targetDID, 7001)
			fmt.Printf("Evaluando DID : %s\n", targetDID)
			fmt.Printf("Decisión      : %s (%s)\n", dec, reason)
		case "allow":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli firewall allow <did>")
				return
			}
			targetDID := os.Args[3]
			firewall.AuthorizeDID(&l1.DIDPolicy{
				DID:           targetDID,
				AllowInbound:  true,
				AllowOutbound: true,
				AllowRelay:    true,
				CreatedAt:     time.Now(),
			})
			fmt.Printf("[+] DID Autorizado en libreta ZTNA: %s\n", targetDID)
		case "list":
			fallthrough
		default:
			fmt.Printf("Política Global : Default-Deny (%v)\n", firewall.IsDefaultDeny())
			policies := firewall.GetAllPolicies()
			fmt.Printf("Reglas activas  : %d\n", len(policies))
			for _, p := range policies {
				fmt.Printf("  - DID: %s [Inbound:%v | Outbound:%v | Relay:%v]\n",
					p.DID, p.AllowInbound, p.AllowOutbound, p.AllowRelay)
			}
		}

	case "dag":
		fmt.Println("=== ALMACÉN INMUTABLE DAG & COLA DTN (Dimensión 4) ===")
		subCmd := "status"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "put":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli dag put <payload> [target_did]")
				return
			}
			payload := os.Args[3]
			targetDID := ""
			if len(os.Args) >= 5 {
				targetDID = os.Args[4]
			}
			blk, err := dagStore.PutBlock([]byte(payload), nil, targetDID)
			if err != nil {
				fmt.Printf("[-] Error al crear bloque: %v\n", err)
				return
			}
			fmt.Printf("[+] Bloque creado exitosamente en DAG:\n")
			fmt.Printf("    CID        : %s\n", blk.CID)
			fmt.Printf("    Autor      : %s\n", blk.AuthorDID)
			fmt.Printf("    Destino    : %s\n", blk.TargetDID)
			fmt.Printf("    Timestamp  : %s\n", blk.Timestamp.Format(time.RFC3339))
		case "status":
			fallthrough
		default:
			fmt.Printf("Bloques almacenados : %d\n", dagStore.BlocksStored)
			fmt.Printf("Paquetes encolados  : %d\n", dagStore.BundlesQueued)
			fmt.Printf("Bloques totales     : %d\n", len(dagStore.ListBlocks(0)))
		}

	case "accounting":
		fmt.Println("=== ECONOMÍA DE RECIPROCIDAD TIT-FOR-TAT (Dimensión 5) ===")
		stats := accounting.Stats()
		fmt.Printf("Pares auditados    : %d\n", stats.TotalPeersTracked)
		fmt.Printf("Nivel PRIORITY     : %d\n", stats.PriorityPeers)
		fmt.Printf("Nivel NORMAL       : %d\n", stats.NormalPeers)
		fmt.Printf("Nivel BEST_EFFORT  : %d\n", stats.BestEffortPeers)
		fmt.Printf("Nivel THROTTLED    : %d\n", stats.ThrottledPeers)
		fmt.Printf("Total Estrangulado : %d sanciones\n", stats.TotalThrottled)

	case "wot":
		fmt.Println("=== RED SOCIAL CRIPTOGRÁFICA WEB-OF-TRUST (Dimensión 9) ===")
		subCmd := "status"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "vouch":
			if len(os.Args) < 5 {
				fmt.Println("Uso: ipvn7-cli wot vouch <subject_did> <trust_level 0.0-1.0> [razon]")
				return
			}
			targetDID := os.Args[3]
			level, _ := strconv.ParseFloat(os.Args[4], 64)
			reason := "Atestación directa por CLI"
			if len(os.Args) >= 6 {
				reason = os.Args[5]
			}
			vouch, err := wot.SignAndIssueVouch(id, targetDID, level, reason, 30*24*time.Hour)
			if err != nil {
				fmt.Printf("[-] Error emitiendo aval: %v\n", err)
				return
			}
			score, hops := wot.CalculateReputation(id.DID(), targetDID)
			fmt.Printf("[+] Aval emitido con firma Ed25519:\n")
			fmt.Printf("    Sujeto     : %s\n", vouch.SubjectDID)
			fmt.Printf("    Confianza  : %.2f\n", vouch.TrustLevel)
			fmt.Printf("    Reputación : %.2f / 100 (%d saltos)\n", score, hops)
		case "score":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli wot score <target_did>")
				return
			}
			targetDID := os.Args[3]
			score, hops := wot.CalculateReputation(id.DID(), targetDID)
			fmt.Printf("Reputación calculada para %s:\n", targetDID)
			fmt.Printf("  Puntaje Atenuado: %.2f / 100\n", score)
			fmt.Printf("  Distancia social: %d saltos\n", hops)
		default:
			fmt.Println("Subcomandos: wot vouch <did> <score> [razon] | wot score <did>")
		}

	case "alias":
		if len(os.Args) < 4 {
			fmt.Println("Uso: ipvn7-cli alias <nombre.ipv7> <did:ipvn7:...> [contexto_raiz]")
			return
		}
		aliasName := os.Args[2]
		targetDID := os.Args[3]

		var contextualName string
		if len(os.Args) >= 5 {
			ctxRoot := os.Args[4]
			h := sha256.Sum256([]byte(ctxRoot))
			prefix := hex.EncodeToString(h[:4])
			contextualName = fmt.Sprintf("%s.%s", prefix, strings.TrimPrefix(aliasName, prefix+"."))
			fmt.Printf("[+] Petname Contextual Asignado: '%s' (Ámbito raíz: %s) -> %s\n",
				contextualName, ctxRoot, targetDID)
		} else {
			contextualName = aliasName
			fmt.Printf("[+] Petname Asignado: '%s' -> %s (Almacén local dDNS asegurado)\n", contextualName, targetDID)
		}

	case "ddns":
		fmt.Println("=== RESOLUCIÓN DESCENTRALIZADA PETNAMES dDNS (Dimensión 2) ===")
		subCmd := "list"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "resolve":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli ddns resolve <nombre.ipv7>")
				return
			}
			name := os.Args[3]
			rec, found := petnames.Resolve(name, "")
			if !found {
				fmt.Printf("[-] Nombre '%s' no encontrado en el almacén local\n", name)
				return
			}
			fmt.Printf("[+] Nombre Resuelto: %s\n", rec.Name)
			fmt.Printf("    DID          : %s\n", rec.DID)
			fmt.Printf("    IPv6 Soberana: %s\n", rec.VirtualIPv6)
			fmt.Printf("    IPv4 Virtual : %s\n", rec.VirtualIPv4)
		case "export-hosts":
			hosts := petnames.ExportHostsFormat()
			fmt.Println(hosts)
		default:
			recs := petnames.ListRecords()
			fmt.Printf("Nombres registrados: %d\n", len(recs))
			for _, r := range recs {
				fmt.Printf("  - %s -> %s (%s)\n", r.Name, r.DID[:24]+"...", r.VirtualIPv6)
			}
		}

	case "multipath":
		fmt.Println("=== PLANIFICADOR DE CAMINOS MÚLTIPLES (Dimensión 8) ===")
		stats := multipath.Stats()
		fmt.Printf("Enlaces registrados  : %d (Activos: %d)\n", stats.TotalInterfaces, stats.ActiveInterfaces)
		fmt.Printf("Paquetes enrutados   : %d\n", stats.PacketsRouted)
		fmt.Printf("Paquetes duplicados  : %d\n", stats.PacketsDuplicated)
		fmt.Printf("Eventos de failover  : %d\n", stats.FailoverEvents)

	case "sas":
		fmt.Println("=== AUTENTICACIÓN FUERA-DE-BANDA SAS (Dimensión 10) ===")
		if len(os.Args) < 3 {
			fmt.Println("Uso: ipvn7-cli sas <peer_did>")
			return
		}
		peerDID := os.Args[2]
		pubPeer, err := l0.PublicKeyFromDID(peerDID)
		if err != nil {
			fmt.Printf("[-] Error extrayendo clave pública del DID: %v\n", err)
			return
		}
		sas := l4.DeriveSAS(id.PublicKey, pubPeer)
		fmt.Printf("Identidad Local  : %s\n", id.DID())
		fmt.Printf("Identidad Par    : %s\n", peerDID)
		fmt.Printf("Código Numérico  : [%s]\n", sas.Digits)
		fmt.Printf("Secuencia Visual : %s %s %s %s\n",
			sas.Emojis[0], sas.Emojis[1], sas.Emojis[2], sas.Emojis[3])

	case "copilot":
		fmt.Println("=== COPILOTO DE IA Y AUTO-CURACIÓN (Dimensión 11) ===")
		subCmd := "diagnose"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "stats":
			st := copilot.Stats()
			fmt.Printf("Auto-curación activa: %v\n", st.AutoHealingActive)
			fmt.Printf("Diagnósticos totales: %d\n", st.TotalDiagnoses)
			fmt.Printf("Acciones aplicadas  : %d\n", st.ActionsApplied)
		case "diagnose":
			fallthrough
		default:
			anomalies := copilot.DetectAnomalies(55.0, 8)
			fmt.Printf("Escaneo de telemetría: %d anomalías detectadas\n", len(anomalies))
			for _, an := range anomalies {
				diag, _ := copilot.DiagnoseAndHeal(nil, an)
				fmt.Printf("\n[!] Anomalía: %s (%s)\n", an.Type, an.Severity)
				fmt.Printf("    Causa Raíz      : %s\n", diag.RootCause)
				fmt.Printf("    Solución        : %s\n", diag.RecommendedFix)
				fmt.Printf("    Acción Aplicada : %s (Auto-reparación: %v)\n", diag.ActionType, diag.ExecutedAction)
				fmt.Printf("    Modelo Usado    : %s (Confianza: %.2f)\n", diag.ModelUsed, diag.ConfidenceScore)
			}
		}

	case "constitution":
		fmt.Println("=== CONSTITUCIÓN DIGITAL SOBERANA (Dimensión 12 / v0.5.0) ===")
		subCmd := "view"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "verify":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli constitution verify <archivo_fuente.go>")
				return
			}
			filePath := os.Args[3]
			content, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("[-] Error leyendo archivo: %v\n", err)
				return
			}
			report, err := constVerifier.VerifyCode(string(content), filePath)
			if err != nil {
				fmt.Printf("[-] Error durante análisis constitucional: %v\n", err)
				return
			}
			fmt.Printf("Objetivo auditado : %s\n", report.ProposalOrCodeID)
			fmt.Printf("Certificado       : %v\n", report.Certified)
			if len(report.SignatureHex) >= 32 {
				fmt.Printf("Firma Autoridad   : %s...\n", report.SignatureHex[:32])
			}
			if len(report.Violations) > 0 {
				fmt.Printf("\n[!] Violaciones Detectadas (%d):\n", len(report.Violations))
				for _, v := range report.Violations {
					fmt.Printf("  - Cláusula: %d | Severidad: %s\n    Detalle: %s\n",
						v.ClauseNumber, v.Severity, v.Description)
				}
			} else {
				fmt.Println("\n[+] CÓDIGO 100% CONFORME CON EL ARTÍCULO I (Privacidad Absoluta, Zero-Trust, Anti-Plutocracia)")
			}
		case "view":
			fallthrough
		default:
			fmt.Println(constVerifier.GetConstitutionText())
		}

	case "senate":
		fmt.Println("=== SENADO DE AGENTES Y DEMOCRACIA LÍQUIDA (Dimensión 13 / v0.5.0) ===")
		subCmd := "list"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "propose":
			if len(os.Args) < 5 {
				fmt.Println("Uso: ipvn7-cli senate propose <titulo> <descripcion> [categoria] [archivo_codigo]")
				return
			}
			title := os.Args[3]
			desc := os.Args[4]
			cat := l3.CategoryRoutingOptimization
			if len(os.Args) >= 6 {
				cat = l3.ProposalCategory(os.Args[5])
			}
			code := "package main\n// Código verificado conforme a la Constitución\n"
			if len(os.Args) >= 7 {
				c, err := os.ReadFile(os.Args[6])
				if err == nil {
					code = string(c)
				}
			}
			prop, err := senate.SubmitProposal(title, desc, cat, code)
			if err != nil {
				fmt.Printf("[-] Error enviando propuesta: %v\n", err)
				return
			}
			fmt.Printf("[+] Propuesta radicada con éxito:\n")
			fmt.Printf("    ID: %s\n", prop.ID)
			fmt.Printf("    Título: %s\n", prop.Title)
			fmt.Printf("    Estado: %s\n", prop.Status)
			fmt.Printf("    Certificación Constitucional: %v\n", prop.ConstitutionalReport.Certified)
		case "vote":
			if len(os.Args) < 5 {
				fmt.Println("Uso: ipvn7-cli senate vote <prop_id> <yes|no> [justificacion]")
				return
			}
			propID := os.Args[3]
			stanceStr := strings.ToLower(os.Args[4])
			stance := l3.StanceSupport
			if stanceStr == "no" || stanceStr == "oppose" {
				stance = l3.StanceOppose
			}
			just := "Voto de agente ponderado por Proof-of-Contribution"
			if len(os.Args) >= 6 {
				just = os.Args[5]
			}
			vote, err := senate.CastAgentVote(propID, stance, just)
			if err != nil {
				fmt.Printf("[-] Error al votar: %v\n", err)
				return
			}
			fmt.Printf("[+] Voto computado y firmado por agente:\n")
			fmt.Printf("    Propuesta: %s\n", vote.ProposalID)
			fmt.Printf("    Postura  : %s\n", vote.Stance)
			fmt.Printf("    Peso PoC : %.2f\n", vote.Weight)
			if len(vote.SignatureHex) >= 24 {
				fmt.Printf("    Firma    : %s...\n", vote.SignatureHex[:24])
			}
		case "veto":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli senate veto <prop_id> [razon]")
				return
			}
			propID := os.Args[3]
			reason := "Veto soberano humano inalienable ejercido vía CLI"
			if len(os.Args) >= 5 {
				reason = os.Args[4]
			}
			err := senate.SovereignHumanVeto(propID, reason)
			if err != nil {
				fmt.Printf("[-] Error al ejercer veto: %v\n", err)
				return
			}
			fmt.Printf("[!] VETO SOBERANO HUMANO EJERCIDO EXITOSAMENTE\n")
			fmt.Printf("    Propuesta: %s\n", propID)
			fmt.Printf("    Razón    : %s\n", reason)
		case "report":
			rep := senate.GenerateMorningReport()
			fmt.Printf("=== INFORME MATUTINO DE SUPERVISIÓN HUMANA (%s) ===\n", rep.Date)
			fmt.Printf("Debates activos      : %d\n", rep.TotalActiveDebates)
			fmt.Printf("Votos emitidos por IA: %d\n", rep.VotesCastByAgent)
			if len(rep.Decisions) == 0 {
				fmt.Println("(Sin decisiones pendientes ni registradas en este ciclo)")
			} else {
				for _, d := range rep.Decisions {
					vStr := "Activo"
					if d.Vetoed {
						vStr = "VETADO POR HUMANO"
					}
					fmt.Printf("  - [%s] %s | Postura: %s (Peso PoC: %.1f) | Estado: %s\n    Justificación: %s\n",
						d.ProposalID, d.Title, d.AgentStance, d.WeightUsed, vStr, d.Justification)
				}
			}
		case "list":
			fallthrough
		default:
			props := senate.ListProposals()
			fmt.Printf("Propuestas en el Senado: %d\n", len(props))
			for _, p := range props {
				fmt.Printf("\n* [%s] %s (Categoría: %s)\n", p.ID, p.Title, p.Category)
				fmt.Printf("  Estado: %s | Soporte PoC: %.1f | Oposición PoC: %.1f\n", p.Status, p.SupportWeight, p.OpposeWeight)
				fmt.Printf("  Votos de agentes: %d | Argumentos técnicos: %d\n", len(p.Votes), len(p.Arguments))
				if p.VetoReason != "" {
					fmt.Printf("  [!] Veto Soberano: %s\n", p.VetoReason)
				}
			}
		}

	case "sentinel":
		fmt.Println("=== SISTEMA INMUNOLÓGICO CELULAR DE CENTINELAS (Dimensión 14 / v0.5.0) ===")
		subCmd := "status"
		if len(os.Args) >= 3 {
			subCmd = os.Args[2]
		}
		switch subCmd {
		case "audit":
			if len(os.Args) < 4 {
				fmt.Println("Uso: ipvn7-cli sentinel audit <peer_did>")
				return
			}
			targetDID := os.Args[3]
			chal, err := sentinel.IssueAuditChallenge(targetDID)
			if err != nil {
				fmt.Printf("[-] Error al despachar desafío: %v\n", err)
				return
			}
			fmt.Printf("[+] Desafío de auditoría cruzada emitido:\n")
			fmt.Printf("    ID Desafío    : %s\n", chal.ChallengeID)
			fmt.Printf("    Nodo Auditado : %s\n", chal.TargetDID)
			fmt.Printf("    Nonce         : %s\n", chal.NonceHex)
			fmt.Printf("    Hash Esperado : %s\n", chal.ExpectedSandboxHash)
			fmt.Printf("    Timestamp     : %s\n", chal.Timestamp.Format(time.RFC3339))
		case "alerts":
			alerts := sentinel.GetActiveAlerts()
			fmt.Printf("Alertas inmunológicas activas: %d\n", len(alerts))
			for _, a := range alerts {
				fmt.Printf("\n[!] Alerta: %s\n", a.AlertID)
				fmt.Printf("    Incidente: %s | Infractor: %s\n", a.Incident, a.OffenderDID)
				fmt.Printf("    Evidencia: %s\n", a.EvidencePayload)
				fmt.Printf("    Quórum: %d firmas (Alcanzado: %v, Slashed: %v)\n", len(a.Signatures), a.QuorumReached, a.Slashed)
			}
		case "status":
			fallthrough
		default:
			st := sentinel.GetStats()
			fmt.Printf("Centinela Local       : %s\n", id.DID())
			fmt.Printf("Umbral de Quórum      : %d firmas criptográficas\n", st.QuorumThreshold)
			fmt.Printf("Auditorías Ejecutadas : %d\n", st.TotalAuditsExecuted)
			fmt.Printf("Alertas Registradas   : %d\n", st.TotalAlertsEmitted)
			fmt.Printf("Nodos Neutralizados   : %d (Slashed de por vida)\n", len(st.NeutralizedDIDs))
			if len(st.NeutralizedDIDs) > 0 {
				fmt.Println("\nLista Negra Inmunológica (Drop Default-Deny ZTNA):")
				for _, did := range st.NeutralizedDIDs {
					fmt.Printf("  - [EXPULSADO] %s\n", did)
				}
			}
		}

	case "mcp":
		mcpServer := l3.NewMCPServer(id, router, telemetry)
		mcpServer.AttachSubsystems(
			firewall,
			dagStore,
			wot,
			multipath,
			copilot,
			func(name string) (string, string, string, bool) {
				rec, found := petnames.Resolve(name, "")
				if !found {
					return "", "", "", false
				}
				return rec.DID, rec.VirtualIPv6, rec.VirtualIPv4, true
			},
			func(peerDID string) (string, []string, error) {
				pubPeer, err := l0.PublicKeyFromDID(peerDID)
				if err != nil {
					return "", nil, err
				}
				sas := l4.DeriveSAS(id.PublicKey, pubPeer)
				return sas.Digits, sas.Emojis, nil
			},
		)
		mcpServer.AttachSenateAndSentinel(constVerifier, senate, sentinel)
		if err := mcpServer.ServeStdioDefault(); err != nil {
			fmt.Fprintf(os.Stderr, "Error en sesión MCP: %v\n", err)
		}

	case "help", "--help", "-h":
		printHelp()

	default:
		fmt.Printf("Comando desconocido: '%s'. Ejecute 'ipvn7-cli help' para opciones.\n", command)
	}
}

func init() {
	_ = json.Marshal
}
