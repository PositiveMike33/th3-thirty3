/**
 * Test script for KeelClip Incident Analysis System
 * 
 * This script tests:
 * 1. VisionService - Image analysis via AnythingLLM
 * 2. KeelClipAnalyzer - 5-Why generation
 * 3. Report validation
 */

require('dotenv').config();
const VisionService = require('./vision_service');
const KeelClipAnalyzer = require('./keelclip_analyzer');
const LLMService = require('./llm_service');

async function testIncidentAnalysis() {
    console.log('=== KEELCLIP INCIDENT ANALYSIS TEST ===\n');

    // Initialize services
    const llmService = new LLMService();
    const visionService = new VisionService(llmService);
    const analyzer = new KeelClipAnalyzer(llmService);

    // Test 1: Analyze a sample incident description (text-based)
    console.log('📝 TEST 1: Text-based incident analysis\n');

    
    const sampleIncident = {
        composants_visibles: ['Star Wheel', 'Lug Chain', 'Discharge Selector'],
        defaut_principal: 'Bourrage de cartons au niveau du Star Wheel',
        localisation: 'Star Wheel - Zone de transfert',
        indices_visuels: [
            'Accumulation de cartons',
            'Star Wheel désaligné de 2mm',
            'Traces d\'usure sur les lugs'
        ],
        etat_machine: 'arrêtée',
        risques_securite: ['Risque de coincement lors du redémarrage'],
        hypotheses_causes: [
            'Désalignement du Star Wheel',
            'Usure excessive des lugs',
            'Vitesse de ligne inadaptée'
        ],
        parsed: true
    };

    try {
        console.log('Generating quick summary...');
        const summary = analyzer.generateQuickSummary(sampleIncident);
        console.log('\n' + summary + '\n');

        console.log('Generating 5-Why report...');
        const report = await analyzer.generate5Why(
            sampleIncident,
            'Bourrage au Star Wheel pendant le shift de nuit. Machine arrêtée après 3 bourrages consécutifs.'
        );
        
        console.log('\n=== RAPPORT 5-WHY ===\n');
        console.log(report);
        console.log('\n===================\n');

        // Validate the report
        console.log('Validating report...');
        const validation = analyzer.validate5WhyReport(report);
        
        console.log('\n=== VALIDATION ===');
        console.log(`Score: ${validation.score}/100`);
        console.log(`Valid: ${validation.valid ? '✅' : '❌'}`);
        console.log(`Recommendation: ${validation.recommendation}`);
        
        if (validation.issues.length > 0) {
            console.log('\nIssues detected:');
            validation.issues.forEach(issue => console.log(`  - ${issue}`));
        }
        console.log('==================\n');

    } catch (error) {
        console.error('❌ Test failed:', error.message);
        console.error(error.stack);
    }

    // Test 2: Validate a bad report (should fail)
    console.log('\n📝 TEST 2: Validation of bad report (should fail)\n');
    
    const badReport = `
    Problème: Bourrage machine
    
    Pourquoi 1: L'opérateur n'a pas fait attention
    Pourquoi 2: Il était fatigué
    Pourquoi 3: Erreur humaine
    Pourquoi 4: Manque de concentration
    Pourquoi 5: Faute de l'opérateur
    `;

    const badValidation = analyzer.validate5WhyReport(badReport);
    console.log('=== VALIDATION (BAD REPORT) ===');
    console.log(`Score: ${badValidation.score}/100`);
    console.log(`Valid: ${badValidation.valid ? '✅' : '❌'}`);
    console.log(`Recommendation: ${badValidation.recommendation}`);
    
    if (badValidation.issues.length > 0) {
        console.log('\nIssues detected (expected):');
        badValidation.issues.forEach(issue => console.log(`  - ${issue}`));
    }
    console.log('================================\n');

    // Test 3: Image analysis (if AnythingLLM is configured)
    if (process.env.ANYTHING_LLM_URL && process.env.ANYTHING_LLM_KEY) {
        console.log('📸 TEST 3: Image analysis (skipped - requires actual image file)\n');
        console.log('To test image analysis:');
        console.log('1. Place an image in server/temp/test_incident.jpg');
        console.log('2. Uncomment the code below');
        console.log('3. Ensure AnythingLLM workspace uses a vision model (GPT-4 Vision, Claude 3)\n');

        
        /*
        const fs = require('fs');
        const path = require('path');
        const testImagePath = path.join(__dirname, 'temp', 'test_incident.jpg');
        
        if (fs.existsSync(testImagePath)) {
            console.log('Analyzing test image...');
            const imageAnalysis = await visionService.analyzeKeelClipIncident(testImagePath, 'image');
            console.log('\n=== IMAGE ANALYSIS ===');
            console.log(JSON.stringify(imageAnalysis, null, 2));
            console.log('======================\n');
        }
        */
    } else {
        console.log('⚠️  AnythingLLM not configured - Skipping image analysis test');
        console.log('   Set ANYTHING_LLM_URL and ANYTHING_LLM_KEY in .env\n');
    }

    console.log('=== ALL TESTS COMPLETE ===\n');
}

// Run tests
testIncidentAnalysis().catch(err => {
    console.error('FATAL ERROR:', err);
    process.exit(1);
});
