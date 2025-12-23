/**
 * Test du Service d'Extraction avec Llama 3.2
 * Exécuter: node test_extraction.js
 */

require('dotenv').config();
const ReportExtractionService = require('./report_extraction_service');

const extraction = new ReportExtractionService();

async function runTest() {
    console.log('🔬 === TEST EXTRACTION LLAMA 3.2 ===\n');

    // Test 1: Extraction d'incident
    const testDescription = `
    Bourrage répétitif sur Star Wheel ligne 1 pendant le shift de nuit.
    Désalignement de 2mm observé, les clips ne sont pas correctement indexés.
    Usure visible sur les Lugs. Production arrêtée 45 minutes.
    `;

    console.log('📝 Description incident:');
    console.log(testDescription);
    console.log('\n' + '═'.repeat(60) + '\n');

    try {
        // Traitement complet
        console.log('⏳ Traitement en cours avec Llama 3.2...\n');
        const result = await extraction.processIncident(testDescription);

        // Afficher le rapport 5P généré
        console.log('═'.repeat(60));
        console.log('📊 RAPPORT 5-POURQUOI GÉNÉRÉ:');
        console.log('═'.repeat(60));
        console.log(result.report);

        // Simuler un apprentissage
        console.log('\n' + '═'.repeat(60));
        console.log('🧠 SIMULATION APPRENTISSAGE...');
        console.log('═'.repeat(60) + '\n');

        extraction.learnFromResolution(
            {
                component: 'Star Wheel',
                defect: 'Bourrage',
                tags: ['désalignement', 'usure', 'ligne1']
            },
            {
                rootCause: 'CIL incomplet - vérification alignement non incluse',
                preventiveAction: 'Ajouter point vérification alignement au CIL quotidien'
            }
        );

        // Afficher les stats d'apprentissage
        console.log('📈 Statistiques apprentissage:');
        const stats = extraction.getLearningStats();
        console.log(JSON.stringify(stats, null, 2));

        // Test suggestions
        console.log('\n💡 Suggestions pour "Star Wheel":');
        const suggestions = extraction.getSuggestions('Star Wheel', 'Bourrage');
        console.log(JSON.stringify(suggestions, null, 2));

    } catch (error) {
        console.error('❌ Erreur:', error.message);
        console.log('\n💡 Vérifiez que:');
        console.log('   1. Ollama est démarré (ollama serve)');
        console.log('   2. Llama 3.2 Vision est installé (ollama pull qwen2.5-coder:7b)');
    }

    console.log('\n✅ Test terminé');
}

runTest();
