/**
 * Script d'intégration de l'analyse de sécurité hybride dans AnythingLLM
 * Enrichit la base de connaissances avec les données de l'analyse
 */

const fs = require('fs');
const path = require('path');
const settingsService = require('./settings_service');

const ANALYSIS_CONTENT = {
    title: "Analyse de Sécurité Hybride IT/OT",
    date: "2025-12-15",
    
    risks: [
        {
            id: "RISK-001",
            description: "Dépendance à l'intervention humaine pour les cas limites - algorithmes de sécurité manquant de fiabilité critique",
            level: "CRITIQUE",
            category: "algorithmic_reliability"
        },
        {
            id: "RISK-002", 
            description: "Attaques cyber-cinétiques présentant un risque immédiat pour la sécurité physique des employés",
            level: "CRITIQUE",
            category: "cyber_kinetic"
        },
        {
            id: "RISK-003",
            description: "Ingénierie sociale ciblant la main-d'œuvre industrielle - manque de sensibilisation",
            level: "ÉLEVÉ",
            category: "social_engineering"
        },
        {
            id: "RISK-004",
            description: "Mauvaise interprétation des données numériques lors d'une crise physique",
            level: "CRITIQUE",
            category: "data_interpretation"
        },
        {
            id: "RISK-005",
            description: "Absence de protocoles traduits en langage opérationnel - personnel vulnérable",
            level: "ÉLEVÉ",
            category: "protocol_translation"
        }
    ],
    
    recommendations: [
        "Intégrer les protocoles de cybersécurité aux procédures SSE existantes",
        "Organiser des simulations de crise IT/OT régulières",
        "Définir l'autorité décisionnelle humaine vs capteurs",
        "Renforcer les contrôles d'accès physique post-audit Red Team",
        "Former les cadres à la manipulation psychologique",
        "Établir des canaux de communication hors bande",
        "Auditer les interfaces homme-machine",
        "Créer un lexique commun cyber/opérations",
        "Mettre en place des vérifications manuelles pour commandes critiques",
        "Développer des indicateurs de compromission physique"
    ],
    
    trends: [
        "Convergence IT/OT nécessitant une traduction constante",
        "Facteur humain comme mécanisme de sécurité ultime",
        "Audits incluant des intrusions physiques réelles",
        "Psychologie de la main-d'œuvre comme vecteur d'attaque",
        "Scénarios cyber-cinétiques pour planification de continuité",
        "Interprétation humaine experte pour les cas limites IA",
        "Approche holistique numérique/physique",
        "Manipulation sociale contournant les défenses tech",
        "Protocoles simplifiés pour personnel non technique",
        "Décisions rapides avec données corrompues"
    ]
};

async function integrateToAnythingLLM() {
    console.log('=== INTEGRATION ANYTHINGLLM ===\n');
    
    const settings = settingsService.getSettings();
    const url = settings?.apiKeys?.anythingllm_url;
    const key = settings?.apiKeys?.anythingllm_key;
    
    if (!url || !key) {
        console.error('❌ AnythingLLM non configuré');
        return false;
    }
    
    const workspaces = ['cybersecurite', 'osint', 'th3-thirty3-workspace'];
    
    for (const workspace of workspaces) {
        console.log(`\n📤 Envoi vers workspace: ${workspace}`);
        
        try {
            // Envoyer les risques
            const risksMessage = `
[KNOWLEDGE_BASE] Analyse de Sécurité Hybride IT/OT - RISQUES IDENTIFIÉS:

${ANALYSIS_CONTENT.risks.map(r => `
🔴 ${r.id} (${r.level}): ${r.description}
   Catégorie: ${r.category}
`).join('\n')}

Mémorise ces risques pour les futures analyses de sécurité industrielle.
`;
            
            await sendToWorkspace(url, key, workspace, risksMessage);
            console.log(`   ✅ Risques envoyés`);
            
            // Envoyer les recommandations
            const recsMessage = `
[KNOWLEDGE_BASE] Analyse de Sécurité Hybride IT/OT - RECOMMANDATIONS:

${ANALYSIS_CONTENT.recommendations.map((r, i) => `${i+1}. ${r}`).join('\n')}

Ces recommandations sont essentielles pour la sécurité cyber-cinétique industrielle.
`;
            
            await sendToWorkspace(url, key, workspace, recsMessage);
            console.log(`   ✅ Recommandations envoyées`);
            
            // Envoyer les tendances
            const trendsMessage = `
[KNOWLEDGE_BASE] Analyse de Sécurité Hybride IT/OT - TENDANCES 2025:

${ANALYSIS_CONTENT.trends.map((t, i) => `📈 ${t}`).join('\n')}

Ces tendances définissent l'évolution de la sécurité industrielle moderne.
`;
            
            await sendToWorkspace(url, key, workspace, trendsMessage);
            console.log(`   ✅ Tendances envoyées`);
            
        } catch (error) {
            console.error(`   ❌ Erreur workspace ${workspace}:`, error.message);
        }
        
        // Délai entre workspaces
        await new Promise(r => setTimeout(r, 1000));
    }
    
    console.log('\n✅ Intégration AnythingLLM terminée!');
    return true;
}

async function sendToWorkspace(url, key, workspace, message) {
    const response = await fetch(`${url}/workspace/${workspace}/chat`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${key}`
        },
        body: JSON.stringify({
            message,
            mode: 'chat'
        })
    });
    
    if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
    }
    
    return await response.json();
}

// Export pour utilisation programmatique
module.exports = { integrateToAnythingLLM, ANALYSIS_CONTENT };

// Exécution directe
if (require.main === module) {
    integrateToAnythingLLM()
        .then(() => process.exit(0))
        .catch(err => {
            console.error('Erreur:', err);
            process.exit(1);
        });
}
