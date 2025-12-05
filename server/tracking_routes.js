/**
 * API Routes pour le système de tracking 5-Why
 * À intégrer dans le serveur Express principal
 */

const express = require('express');
const router = express.Router();
const TrackingService = require('./tracking_service');
const EmailReminderService = require('./email_reminder_service');

const tracking = new TrackingService();
const emailService = new EmailReminderService();

// ============================================
// ROUTES TECHNICIENS
// ============================================

/**
 * GET /api/tracking/technicians
 * Obtenir tous les techniciens actifs
 */
router.get('/technicians', (req, res) => {
    const { role, shift } = req.query;
    const technicians = tracking.getTechnicians({ role, shift });
    res.json({ success: true, technicians });
});

/**
 * POST /api/tracking/technicians
 * Ajouter un nouveau technicien
 */
router.post('/technicians', (req, res) => {
    const { name, email, role, shift, department } = req.body;
    
    if (!name || !email || !role) {
        return res.status(400).json({ 
            success: false, 
            error: 'name, email et role sont requis' 
        });
    }

    if (!['mecano', 'electro', 'supervisor'].includes(role)) {
        return res.status(400).json({ 
            success: false, 
            error: 'role doit être: mecano, electro ou supervisor' 
        });
    }

    const technician = tracking.addTechnician({ 
        name, email, role, shift, department 
    });
    
    res.json({ success: true, technician });
});

/**
 * PUT /api/tracking/technicians/:id
 * Mettre à jour un technicien
 */
router.put('/technicians/:id', (req, res) => {
    const { id } = req.params;
    const updates = req.body;
    
    const technician = tracking.updateTechnician(id, updates);
    
    if (!technician) {
        return res.status(404).json({ 
            success: false, 
            error: 'Technicien non trouvé' 
        });
    }
    
    res.json({ success: true, technician });
});

/**
 * DELETE /api/tracking/technicians/:id
 * Désactiver un technicien
 */
router.delete('/technicians/:id', (req, res) => {
    const { id } = req.params;
    const technician = tracking.deactivateTechnician(id);
    
    if (!technician) {
        return res.status(404).json({ 
            success: false, 
            error: 'Technicien non trouvé' 
        });
    }
    
    res.json({ success: true, message: 'Technicien désactivé' });
});

// ============================================
// ROUTES INCIDENTS
// ============================================

/**
 * GET /api/tracking/incidents
 * Obtenir les incidents (avec filtres)
 */
router.get('/incidents', (req, res) => {
    const { status, search } = req.query;
    
    let incidents;
    if (search) {
        incidents = tracking.searchIncidents(search);
    } else if (status === 'open') {
        incidents = tracking.getOpenIncidents();
    } else {
        incidents = tracking.incidents;
    }
    
    res.json({ success: true, incidents });
});

/**
 * GET /api/tracking/incidents/:id
 * Obtenir un incident spécifique
 */
router.get('/incidents/:id', (req, res) => {
    const incident = tracking.incidents.find(i => i.id === req.params.id);
    
    if (!incident) {
        return res.status(404).json({ 
            success: false, 
            error: 'Incident non trouvé' 
        });
    }
    
    res.json({ success: true, incident });
});

/**
 * POST /api/tracking/incidents
 * Créer un nouvel incident
 */
router.post('/incidents', async (req, res) => {
    const incidentData = req.body;
    
    if (!incidentData.title) {
        return res.status(400).json({ 
            success: false, 
            error: 'title est requis' 
        });
    }

    const incident = tracking.createIncident(incidentData);
    
    // Envoyer notification aux techniciens assignés
    if (incidentData.assignedTo && incidentData.assignedTo.length > 0) {
        await emailService.sendNewIncidentNotification(incident, incidentData.assignedTo);
    }
    
    res.json({ success: true, incident });
});

/**
 * PUT /api/tracking/incidents/:id/status
 * Mettre à jour le statut d'un incident
 */
router.put('/incidents/:id/status', (req, res) => {
    const { id } = req.params;
    const { status, updatedBy, notes } = req.body;
    
    const validStatuses = ['open', 'in_progress', 'pending_verification', 'resolved', 'closed'];
    if (!validStatuses.includes(status)) {
        return res.status(400).json({ 
            success: false, 
            error: `status doit être: ${validStatuses.join(', ')}` 
        });
    }

    const incident = tracking.updateIncidentStatus(id, status, updatedBy, notes);
    
    if (!incident) {
        return res.status(404).json({ 
            success: false, 
            error: 'Incident non trouvé' 
        });
    }
    
    res.json({ success: true, incident });
});

/**
 * PUT /api/tracking/incidents/:id/action
 * Marquer une action comme complétée
 */
router.put('/incidents/:id/action', (req, res) => {
    const { id } = req.params;
    const { actionType, completedBy, notes } = req.body;
    
    if (!['corrective', 'preventive'].includes(actionType)) {
        return res.status(400).json({ 
            success: false, 
            error: 'actionType doit être: corrective ou preventive' 
        });
    }

    const incident = tracking.completeAction(id, actionType, completedBy, notes);
    
    if (!incident) {
        return res.status(404).json({ 
            success: false, 
            error: 'Incident non trouvé' 
        });
    }
    
    res.json({ success: true, incident });
});

/**
 * PUT /api/tracking/incidents/:id/assign
 * Assigner des techniciens à un incident
 */
router.put('/incidents/:id/assign', async (req, res) => {
    const { id } = req.params;
    const { technicianIds, assignedBy } = req.body;
    
    const incident = tracking.assignTechnicians(id, technicianIds, assignedBy);
    
    if (!incident) {
        return res.status(404).json({ 
            success: false, 
            error: 'Incident non trouvé' 
        });
    }

    // Envoyer notification aux techniciens
    if (technicianIds && technicianIds.length > 0) {
        await emailService.sendNewIncidentNotification(incident, technicianIds);
    }
    
    res.json({ success: true, incident });
});

/**
 * GET /api/tracking/incidents/:id/history
 * Obtenir l'historique d'un incident
 */
router.get('/incidents/:id/history', (req, res) => {
    const history = tracking.getIncidentHistory(req.params.id);
    
    if (!history) {
        return res.status(404).json({ 
            success: false, 
            error: 'Incident non trouvé' 
        });
    }
    
    res.json({ success: true, history });
});

// ============================================
// ROUTES DASHBOARD & RAPPELS
// ============================================

/**
 * GET /api/tracking/dashboard
 * Obtenir le tableau de bord
 */
router.get('/dashboard', (req, res) => {
    const dashboard = tracking.getDashboard();
    res.json({ success: true, dashboard });
});

/**
 * POST /api/tracking/reminders/send
 * Envoyer les rappels manuellement
 */
router.post('/reminders/send', async (req, res) => {
    await emailService.checkAndSendReminders();
    res.json({ 
        success: true, 
        message: 'Rappels vérifiés et envoyés' 
    });
});

/**
 * POST /api/tracking/reminders/start
 * Démarrer les rappels automatiques
 */
router.post('/reminders/start', (req, res) => {
    const { intervalMinutes } = req.body;
    emailService.startAutoReminders(intervalMinutes || 60);
    res.json({ 
        success: true, 
        message: `Rappels automatiques démarrés (intervalle: ${intervalMinutes || 60} min)` 
    });
});

/**
 * POST /api/tracking/reminders/stop
 * Arrêter les rappels automatiques
 */
router.post('/reminders/stop', (req, res) => {
    emailService.stopAutoReminders();
    res.json({ 
        success: true, 
        message: 'Rappels automatiques arrêtés' 
    });
});

/**
 * POST /api/tracking/summary
 * Envoyer un résumé quotidien
 */
router.post('/summary', async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            error: 'email requis' 
        });
    }

    await emailService.sendDailySummary(email);
    res.json({ 
        success: true, 
        message: `Résumé envoyé à ${email}` 
    });
});

module.exports = router;
