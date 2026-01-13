/**
 * Script d'entraînement - Zero-Click Attacks et Agents IA
 * Entraîne l'agent cybersec avec les connaissances sur les attaques zero-click
 */

const ExpertAgentsService = require('./expert_agents_service');
const AgentMemoryService = require('./agent_memory_service');
const fs = require('fs');
const path = require('path');

async function trainZeroClickKnowledge() {
    console.log('\n🎯 ENTRAÎNEMENT: Attaques Zero-Click et Agents IA\n');

    const experts = new ExpertAgentsService();
    const memory = new AgentMemoryService();

    // Charger les données d'entraînement
    const trainingData = JSON.parse(
        fs.readFileSync(path.join(__dirname, 'data', 'training', 'zero_click_attacks.json'), 'utf8')
    );

    // Préparer les connaissances pour l'agent cybersec
    const knowledgeItems = [
        // Définition
        `ZERO-CLICK ATTACK - Définition: ${trainingData.ce_que_cest.definition}`,
        `ZERO-CLICK ATTACK - Origine: ${trainingData.ce_que_cest.origine}`,
        `ZERO-CLICK ATTACK - Vecteurs d'attaque: ${trainingData.ce_que_cest.vecteurs}`,

        // Ce que ça fait
        `ZERO-CLICK IMPACT - Exécution code à distance: ${trainingData.ce_que_ca_fait.execution_code_distance}`,
        `ZERO-CLICK IMPACT - Surveillance totale: ${trainingData.ce_que_ca_fait.surveillance_totale}`,
        `ZERO-CLICK IMPACT - Exfiltration via IA: ${trainingData.ce_que_ca_fait.exfiltration_via_IA}`,

        // Défenses
        `ZERO-CLICK DEFENSE - Fondamentaux: ${trainingData.comment_defendre.fondamentaux}`,
        `ZERO-CLICK DEFENSE - Stratégie Zero Trust: ${trainingData.comment_defendre.strategie_zero_trust}`,
    ];

    // Ajouter les défenses spécifiques IA
    trainingData.comment_defendre.securite_specifique_IA.forEach(item => {
        knowledgeItems.push(`ZERO-CLICK DEFENSE IA - ${item.principe}: ${item.action}`);
    });

    console.log(`📚 ${knowledgeItems.length} éléments de connaissance à stocker...\n`);

    // Stocker chaque élément dans la mémoire de l'agent
    for (const knowledge of knowledgeItems) {
        console.log(`  → ${knowledge.substring(0, 60)}...`);

        // Enseigner à l'expert cybersec
        experts.teachExpert('cybersec', knowledge);

        // Stocker avec embedding vectoriel
        await memory.storeKnowledge('cybersec', knowledge, {
            source: 'training',
            topic: 'zero-click-attacks',
            category: knowledge.split(' - ')[0]
        });
    }

    console.log('\n✅ Entraînement terminé!');

    // Tester avec une question
    console.log('\n🧪 Test de validation...\n');

    try {
        const testResult = await experts.consultExpert(
            'cybersec',
            'Comment se défendre contre une attaque zero-click qui exploite des agents IA?',
            'Context: L\'utilisateur veut comprendre les défenses spécifiques aux attaques zero-click utilisant des agents IA.'
        );

        console.log(`\n${testResult.emoji} ${testResult.name}:`);
        console.log(testResult.response.substring(0, 500) + '...');
    } catch (error) {
        console.log('⚠️ Test skipped (Ollama not available):', error.message);
    }

    // Statistiques finales
    const stats = memory.getMemoryStats();
    console.log('\n📊 Statistiques mémoire:', stats);
}

trainZeroClickKnowledge().catch(console.error);
