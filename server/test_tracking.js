/**
 * Script de test et démonstration du système de tracking 5-Why
 * Exécuter: node test_tracking.js
 */

require('dotenv').config();
const TrackingService = require('./tracking_service');
const tracking = new TrackingService();

async function runDemo() {
    console.log('🏭 === DÉMO SYSTÈME DE TRACKING 5-WHY ===\n');

    // ============================================
    // 1. AJOUTER DES TECHNICIENS
    // ============================================
    console.log('👷 1. AJOUT DES TECHNICIENS\n');

    const mecano1 = tracking.addTechnician({
        name: 'Jean-François Tremblay',
        email: 'jf.tremblay@example.com',
        role: 'mecano',
        shift: 'day',
        department: 'packaging'
    });
    console.log(`   ✅ ${mecano1.name} (${mecano1.role}) - ${mecano1.id}`);

    const mecano2 = tracking.addTechnician({
        name: 'Marc Gagnon',
        email: 'marc.gagnon@example.com',
        role: 'mecano',
        shift: 'evening',
        department: 'packaging'
    });
    console.log(`   ✅ ${mecano2.name} (${mecano2.role}) - ${mecano2.id}`);

    const electro1 = tracking.addTechnician({
        name: 'Sophie Lavoie',
        email: 'sophie.lavoie@example.com',
        role: 'electro',
        shift: 'day',
        department: 'packaging'
    });
    console.log(`   ✅ ${electro1.name} (${electro1.role}) - ${electro1.id}`);

    const supervisor = tracking.addTechnician({
        name: 'Pierre Côté',
        email: 'pierre.cote@example.com',
        role: 'supervisor',
        shift: 'day',
        department: 'packaging'
    });
    console.log(`   ✅ ${supervisor.name} (${supervisor.role}) - ${supervisor.id}`);

    console.log(`\n   Total: ${tracking.getTechnicians().length} techniciens\n`);

    // ============================================
    // 2. CRÉER DES INCIDENTS
    // ============================================
    console.log('⚠️ 2. CRÉATION DES INCIDENTS\n');

    const incident1 = tracking.createIncident({
        title: 'Bourrage Star Wheel - Désalignement 2mm',
        description: 'Bourrage répétitif sur Star Wheel, clips non correctement indexés',
        component: 'Star Wheel',
        line: 'Ligne 1',
        priority: 'high',
        rootCause: 'CIL (Clean, Inspect, Lubricate) incomplet - vérification visuelle de l\'alignement non incluse',
        correctiveAction: 'Réaligner le Star Wheel et remplacer les guides usés',
        preventiveAction: 'Ajouter point de vérification alignement au CIL quotidien',
        assignedTo: [mecano1.id, electro1.id],
        supervisor: supervisor.id,
        createdBy: 'Michael'
    });
    console.log(`   ✅ Incident créé: ${incident1.id}`);
    console.log(`      Titre: ${incident1.title}`);
    console.log(`      Priorité: ${incident1.priority}`);
    console.log(`      Assigné à: ${incident1.assignedTo.length} technicien(s)`);

    const incident2 = tracking.createIncident({
        title: 'Hot Melt Gun - Température instable',
        description: 'Température de colle fluctue de ±15°C, collage inconsistant',
        component: 'Hot Melt Glue Gun',
        line: 'Ligne 2',
        priority: 'critical',
        rootCause: 'Thermocouple défectueux - pas de PM planifiée pour remplacement',
        correctiveAction: 'Remplacer thermocouple immédiatement',
        preventiveAction: 'Ajouter remplacement thermocouple au PM annuel',
        assignedTo: [electro1.id],
        supervisor: supervisor.id,
        createdBy: 'Michael'
    });
    console.log(`\n   ✅ Incident créé: ${incident2.id}`);
    console.log(`      Titre: ${incident2.title}`);
    console.log(`      Priorité: ${incident2.priority}`);

    const incident3 = tracking.createIncident({
        title: 'Lug Chain - Usure prématurée',
        description: 'Chaîne montre usure après seulement 500h au lieu de 2000h prévues',
        component: 'Lug Chain',
        line: 'Ligne 1',
        priority: 'medium',
        rootCause: 'Tension incorrecte - Centerline non défini',
        correctiveAction: 'Remplacer chaîne et ajuster tension à 25N',
        preventiveAction: 'Définir Centerline tension (25N ±2N) et OPL de vérification',
        assignedTo: [mecano2.id],
        supervisor: supervisor.id,
        createdBy: 'Michael'
    });
    console.log(`\n   ✅ Incident créé: ${incident3.id}`);

    console.log('\n');

    // ============================================
    // 3. SIMULER LE WORKFLOW
    // ============================================
    console.log('🔄 3. SIMULATION DU WORKFLOW\n');

    // Incident 1: En cours
    console.log(`   ${incident1.id}: Passage en "in_progress"...`);
    tracking.updateIncidentStatus(incident1.id, 'in_progress', mecano1.name, 'Travaux commencés');

    // Incident 1: Action corrective complétée
    console.log(`   ${incident1.id}: Action corrective complétée...`);
    tracking.completeAction(incident1.id, 'corrective', mecano1.name, 'Star Wheel réaligné, nouveaux guides installés');

    // Incident 2: Résolu rapidement (critique)
    console.log(`   ${incident2.id}: Résolution complète...`);
    tracking.updateIncidentStatus(incident2.id, 'in_progress', electro1.name);
    tracking.completeAction(incident2.id, 'corrective', electro1.name, 'Thermocouple remplacé');
    tracking.completeAction(incident2.id, 'preventive', electro1.name, 'Ajouté au plan PM annuel');
    // Le statut passe automatiquement à 'pending_verification'

    console.log('\n');

    // ============================================
    // 4. AFFICHER LE DASHBOARD
    // ============================================
    console.log('📊 4. DASHBOARD DE SUIVI\n');

    const dashboard = tracking.getDashboard();
    
    console.log('   STATISTIQUES:');
    console.log(`   ├── Total incidents: ${dashboard.total}`);
    console.log(`   ├── Ouverts: ${dashboard.byStatus.open}`);
    console.log(`   ├── En cours: ${dashboard.byStatus.in_progress}`);
    console.log(`   ├── Vérification: ${dashboard.byStatus.pending_verification}`);
    console.log(`   ├── Résolus: ${dashboard.byStatus.resolved}`);
    console.log(`   ├── En retard: ${dashboard.overdue}`);
    console.log(`   └── Nécessitant rappel: ${dashboard.needingReminder}`);

    console.log('\n   INCIDENTS RÉCENTS:');
    dashboard.recentIncidents.forEach((inc, i) => {
        const statusEmoji = {
            'open': '🔴',
            'in_progress': '🟡',
            'pending_verification': '🟢',
            'resolved': '✅',
            'closed': '⬛'
        };
        console.log(`   ${i+1}. ${statusEmoji[inc.status]} ${inc.id}: ${inc.title} (${inc.status})`);
    });

    console.log('\n');

    // ============================================
    // 5. AFFICHER L'HISTORIQUE
    // ============================================
    console.log('📜 5. HISTORIQUE INCIDENT CRITIQUE\n');

    const history = tracking.getIncidentHistory(incident2.id);
    console.log(`   Historique de ${incident2.id}:`);
    history.forEach((entry, i) => {
        const time = new Date(entry.timestamp).toLocaleTimeString('fr-CA');
        console.log(`   ${i+1}. [${time}] ${entry.action} ${entry.by ? `par ${entry.by}` : ''}`);
    });

    console.log('\n');

    // ============================================
    // 6. LISTER LES TECHNICIENS
    // ============================================
    console.log('👷 6. ÉQUIPE TECHNIQUE\n');

    const allTechs = tracking.getTechnicians();
    console.log('   MÉCANOS:');
    tracking.getTechnicians({ role: 'mecano' }).forEach(t => {
        console.log(`   • ${t.name} (${t.shift}) - ${t.email}`);
    });

    console.log('\n   ÉLECTROS:');
    tracking.getTechnicians({ role: 'electro' }).forEach(t => {
        console.log(`   • ${t.name} (${t.shift}) - ${t.email}`);
    });

    console.log('\n   SUPERVISEURS:');
    tracking.getTechnicians({ role: 'supervisor' }).forEach(t => {
        console.log(`   • ${t.name} (${t.shift}) - ${t.email}`);
    });

    console.log('\n');

    // ============================================
    // RÉSUMÉ FINAL
    // ============================================
    console.log('=' .repeat(50));
    console.log('✅ DÉMO COMPLÉTÉE\n');
    console.log('📁 Données sauvegardées dans:');
    console.log('   • server/data/technicians.json');
    console.log('   • server/data/incidents.json');
    console.log('\n🔔 Pour activer les rappels automatiques par email:');
    console.log('   1. Configurer SMTP dans .env');
    console.log('   2. POST /api/tracking/reminders/start');
    console.log('\n📧 Variables email à configurer (.env):');
    console.log('   SMTP_HOST=smtp.gmail.com');
    console.log('   SMTP_PORT=587');
    console.log('   SMTP_USER=your-email@gmail.com');
    console.log('   SMTP_PASS=your-app-password');
    console.log('   SMTP_FROM=noreply@keelclip-vpo.com');
    console.log('=' .repeat(50));
}

// Exécuter
runDemo().catch(console.error);
