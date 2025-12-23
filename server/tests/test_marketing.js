/**
 * Test Marketing Service - Génération de contenu marketing
 * Utilise le workspace "marketing" (Fabric) dans AnythingLLM
 */

require('dotenv').config();
const MarketingService = require('./marketing_service');

const marketingService = new MarketingService();

async function testMarketingGeneration() {
    console.log('\n🎯 === TEST GÉNÉRATION CONTENU MARKETING ===\n');

    try {
        // Test 1: Elevator Pitch
        console.log('📢 1. ELEVATOR PITCH (Investor)\n');
        const pitch = await marketingService.generateElevatorPitch('investor');
        console.log(pitch);
        console.log('\n' + '='.repeat(80) + '\n');

        // Test 2: Post LinkedIn
        console.log('💼 2. POST LINKEDIN (Product Launch)\n');
        const linkedinPost = await marketingService.generateLinkedInPost('product_launch');
        console.log(linkedinPost);
        console.log('\n' + '='.repeat(80) + '\n');

        // Test 3: Email Cold Outreach
        console.log('📧 3. EMAIL COLD OUTREACH (Quality Manager)\n');
        const email = await marketingService.generateColdEmail('quality_manager');
        console.log(email);
        console.log('\n' + '='.repeat(80) + '\n');

        // Test 4: Landing Page Hero
        console.log('🌐 4. LANDING PAGE - HERO SECTION\n');
        const heroCopy = await marketingService.generateLandingPageCopy('hero');
        console.log(heroCopy);
        console.log('\n' + '='.repeat(80) + '\n');

        // Test 5: FAQ
        console.log('❓ 5. FAQ - Product\n');
        const faq = await marketingService.generateFAQ('product');
        console.log(faq);
        console.log('\n' + '='.repeat(80) + '\n');

        console.log('✅ Tous les tests réussis!\n');

    } catch (error) {
        console.error('❌ Erreur:', error.message);
        process.exit(1);
    }
}

// Options de génération spécifique
const args = process.argv.slice(2);
const command = args[0];

async function main() {
    if (!command) {
        // Run all tests
        await testMarketingGeneration();
    } else {
        // Run specific generation
        switch (command) {
            case 'pitch':
                const target = args[1] || 'investor';
                console.log(await marketingService.generateElevatorPitch(target));
                break;

            case 'linkedin':
                const topic = args[1] || 'product_launch';
                console.log(await marketingService.generateLinkedInPost(topic));
                break;

            case 'email':
                const recipient = args[1] || 'manufacturing_engineer';
                console.log(await marketingService.generateColdEmail(recipient));
                break;

            case 'landing':
                const section = args[1] || 'hero';
                console.log(await marketingService.generateLandingPageCopy(section));
                break;

            case 'video':
                const duration = args[1] || '3min';
                console.log(await marketingService.generateVideoScript(duration));
                break;

            case 'faq':
                const category = args[1] || 'product';
                console.log(await marketingService.generateFAQ(category));
                break;

            case 'press':
                const event = args[1] || 'product_launch';
                console.log(await marketingService.generatePressRelease(event));
                break;

            default:
                console.log(`❌ Commande inconnue: ${command}`);
                console.log('\nUtilisation:');
                console.log('  node test_marketing.js                    # All tests');
                console.log('  node test_marketing.js pitch [target]     # Elevator pitch');
                console.log('  node test_marketing.js linkedin [topic]   # LinkedIn post');
                console.log('  node test_marketing.js email [recipient]  # Cold email');
                console.log('  node test_marketing.js landing [section]  # Landing page');
                console.log('  node test_marketing.js video [duration]   # Video script');
                console.log('  node test_marketing.js faq [category]     # FAQ');
                console.log('  node test_marketing.js press [event]      # Press release');
                process.exit(1);
        }
    }
}

main();
