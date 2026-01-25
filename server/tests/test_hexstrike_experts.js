/**
 * Test HexStrike Experts System
 * Script de vérification complète du système
 */

const HexStrikeExpertAgentsService = require('../hexstrike_expert_agents_service');

async function testHexStrikeSystem() {
    console.log('\n' + '='.repeat(60));
    console.log('🔥 TEST DU SYSTÈME HEXSTRIKE EXPERTS');
    console.log('='.repeat(60) + '\n');

    const tests = { passed: 0, failed: 0 };

    // Test 1: Initialisation du service
    console.log('\n📋 TEST 1: Initialisation du service');
    console.log('-'.repeat(40));
    try {
        const service = new HexStrikeExpertAgentsService();
        console.log(`✅ Service initialisé avec ${service.agents.size} experts`);
        tests.passed++;
    } catch (error) {
        console.log(`❌ Échec: ${error.message}`);
        tests.failed++;
        return;
    }

    const service = new HexStrikeExpertAgentsService();

    // Test 2: Vérifier les catégories
    console.log('\n📋 TEST 2: Catégories d\'experts');
    console.log('-'.repeat(40));
    try {
        const categories = service.getExpertsByCategory();
        const catNames = Object.keys(categories);
        console.log(`✅ ${catNames.length} catégories trouvées:`);
        for (const cat of catNames) {
            console.log(`   • ${cat}: ${categories[cat].length} experts`);
        }
        tests.passed++;
    } catch (error) {
        console.log(`❌ Échec: ${error.message}`);
        tests.failed++;
    }

    // Test 3: Vérifier les experts disponibles
    console.log('\n📋 TEST 3: Liste des experts');
    console.log('-'.repeat(40));
    try {
        const summary = service.getExpertsSummary();
        console.log(`✅ Total: ${summary.totalExperts} experts`);
        console.log(`✅ Catégories: ${summary.categories}`);

        // Afficher quelques experts
        let count = 0;
        for (const [id, agent] of service.agents) {
            if (count < 5) {
                console.log(`   ${agent.emoji} ${agent.name} (${agent.tool})`);
                count++;
            }
        }
        console.log('   ...');
        tests.passed++;
    } catch (error) {
        console.log(`❌ Échec: ${error.message}`);
        tests.failed++;
    }

    // Test 4: Sélection automatique d'expert
    console.log('\n📋 TEST 4: Auto-sélection d\'expert');
    console.log('-'.repeat(40));
    try {
        const tasks = [
            'scanner les ports ouverts sur une cible',
            'trouver des vulnérabilités SQL injection',
            'découvrir les sous-domaines',
            'cracker un hash MD5'
        ];

        for (const task of tasks) {
            const selected = service.selectExpertForTask(task);
            console.log(`   "${task.substring(0, 35)}..." → [${selected.join(', ')}]`);
        }
        console.log('✅ Auto-sélection fonctionnelle');
        tests.passed++;
    } catch (error) {
        console.log(`❌ Échec: ${error.message}`);
        tests.failed++;
    }

    // Test 5: Consultation d'un expert (sans LLM pour le test rapide)
    console.log('\n📋 TEST 5: Vérification structure experts');
    console.log('-'.repeat(40));
    try {
        const nmapExpert = service.agents.get('nmap');
        if (nmapExpert) {
            console.log(`✅ Expert Nmap trouvé:`);
            console.log(`   Name: ${nmapExpert.name}`);
            console.log(`   Tool: ${nmapExpert.tool}`);
            console.log(`   Category: ${nmapExpert.category}`);
            console.log(`   Commands: ${nmapExpert.commands.length} commandes`);
            console.log(`   SystemPrompt: ${nmapExpert.systemPrompt.substring(0, 50)}...`);
            tests.passed++;
        } else {
            throw new Error('Expert Nmap non trouvé');
        }
    } catch (error) {
        console.log(`❌ Échec: ${error.message}`);
        tests.failed++;
    }

    // Résumé
    console.log('\n' + '='.repeat(60));
    console.log('📊 RÉSUMÉ DES TESTS');
    console.log('='.repeat(60));
    console.log(`✅ Passés: ${tests.passed}`);
    console.log(`❌ Échoués: ${tests.failed}`);
    console.log(`📈 Taux de réussite: ${Math.round(tests.passed / (tests.passed + tests.failed) * 100)}%`);

    if (tests.failed === 0) {
        console.log('\n🎉 TOUS LES TESTS SONT PASSÉS!');
        console.log('Le système HexStrike Experts est opérationnel.\n');
    }

    return tests;
}

// Exécuter les tests
testHexStrikeSystem().catch(console.error);
