/**
 * Email Reminder Service
 * Envoie des rappels automatiques aux techniciens pour le suivi des 5-Why
 */

const nodemailer = require('nodemailer');
const TrackingService = require('./tracking_service');

class EmailReminderService {
    constructor() {
        this.tracking = new TrackingService();

        // Configuration email (à personnaliser dans .env)
        this.transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });

        this.fromEmail = process.env.SMTP_FROM || 'noreply@nexus33-vpo.com';
        this.reminderInterval = null;

        console.log('[EMAIL] Reminder service initialized');
    }

    /**
     * Démarrer les rappels automatiques
     */
    startAutoReminders(intervalMinutes = 60) {
        console.log(`[EMAIL] Starting auto-reminders every ${intervalMinutes} minutes`);

        // Check immédiat
        this.checkAndSendReminders();

        // Puis à intervalle régulier
        this.reminderInterval = setInterval(() => {
            this.checkAndSendReminders();
        }, intervalMinutes * 60 * 1000);
    }

    /**
     * Arrêter les rappels automatiques
     */
    stopAutoReminders() {
        if (this.reminderInterval) {
            clearInterval(this.reminderInterval);
            this.reminderInterval = null;
            console.log('[EMAIL] Auto-reminders stopped');
        }
    }

    /**
     * Vérifier et envoyer les rappels nécessaires
     */
    async checkAndSendReminders() {
        // Warning: TrackingService logic may rely on removed components.
        // Ensure getIncidentsNeedingReminder is generic.
        try {
            const incidents = this.tracking.getIncidentsNeedingReminder();
            console.log(`[EMAIL] Checking reminders: ${incidents.length} incidents need attention`);

            for (const incident of incidents) {
                await this.sendIncidentReminder(incident);
            }
        } catch (error) {
            console.log('[EMAIL] Tracking service or method might be unavailable');
        }
    }

    /**
     * Envoyer un rappel pour un incident
     */
    async sendIncidentReminder(incident) {
        // Obtenir les emails des techniciens assignés
        const technicianEmails = incident.assignedTo
            .map(id => this.tracking.technicians.find(t => t.id === id))
            .filter(t => t && t.active)
            .map(t => t.email);

        if (technicianEmails.length === 0) {
            console.log(`[EMAIL] No technicians assigned to ${incident.id}`);
            return;
        }

        const isOverdue = new Date(incident.dueDate) < new Date();
        const subject = isOverdue
            ? `🚨 URGENT: Incident ${incident.id} - DÉPASSÉ`
            : `⚠️ Rappel: Incident ${incident.id} - Action requise`;

        const html = this.generateReminderEmail(incident, isOverdue);

        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: technicianEmails.join(', '),
                subject: subject,
                html: html
            });

            this.tracking.markReminderSent(incident.id);
            console.log(`[EMAIL] Reminder sent for ${incident.id} to ${technicianEmails.length} technician(s)`);

        } catch (error) {
            console.error(`[EMAIL] Failed to send reminder for ${incident.id}:`, error.message);
        }
    }

    /**
     * Générer le contenu HTML de l'email de rappel
     */
    generateReminderEmail(incident, isOverdue) {
        const urgencyColor = isOverdue ? '#dc3545' : '#ffc107';
        const urgencyText = isOverdue ? 'DÉPASSÉ - ACTION IMMÉDIATE REQUISE' : 'Rappel de suivi';

        return `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: ${urgencyColor}; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f8f9fa; padding: 20px; border: 1px solid #ddd; }
        .info-box { background: white; padding: 15px; border-radius: 8px; margin: 15px 0; border-left: 4px solid #0066cc; }
        .actions { background: #e8f5e9; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .button { display: inline-block; padding: 12px 24px; background: #0066cc; color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
        .status { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; }
        .status-open { background: #fff3cd; color: #856404; }
        .status-in_progress { background: #cce5ff; color: #004085; }
        .status-pending { background: #d4edda; color: #155724; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin:0;">🔧 ${urgencyText}</h2>
            <p style="margin:10px 0 0 0;">Incident #${incident.id}</p>
        </div>
        
        <div class="content">
            <div class="info-box">
                <h3 style="margin-top:0; color: #0066cc;">${incident.title}</h3>
                <p><strong>Composant:</strong> ${incident.component || 'Non spécifié'}</p>
                <p><strong>Ligne:</strong> ${incident.line}</p>
                <p><strong>Priorité:</strong> ${incident.priority.toUpperCase()}</p>
                <p><strong>Statut:</strong> 
                    <span class="status status-${incident.status}">${this.getStatusLabel(incident.status)}</span>
                </p>
                <p><strong>Date limite:</strong> ${new Date(incident.dueDate).toLocaleDateString('fr-CA')}</p>
                <p><strong>Rappels envoyés:</strong> ${incident.remindersSent + 1}</p>
            </div>

            ${incident.rootCause ? `
            <div class="info-box">
                <h4 style="margin-top:0; color: #dc3545;">🎯 Cause Racine Identifiée</h4>
                <p>${incident.rootCause}</p>
            </div>
            ` : ''}

            <div class="actions">
                <h4 style="margin-top:0; color: #28a745;">📋 Actions Requises</h4>
                
                ${incident.correctiveAction ? `
                <p><strong>Action Corrective:</strong> ${incident.correctiveCompleted ? '✅' : '⏳'} ${incident.correctiveAction}</p>
                ` : ''}
                
                ${incident.preventiveAction ? `
                <p><strong>Action Préventive:</strong> ${incident.preventiveCompleted ? '✅' : '⏳'} ${incident.preventiveAction}</p>
                ` : ''}
            </div>

            <p style="text-align: center;">
                <a href="mailto:admin@nexus33.com?subject=Update Incident ${incident.id}&body=Statut de l'incident ${incident.id}:%0D%0A%0D%0AAction complétée: Oui/Non%0D%0ACommentaire:" class="button">
                    📧 Mettre à jour le statut
                </a>
            </p>

            <p style="background: #fff3cd; padding: 15px; border-radius: 8px; text-align: center;">
                <strong>⚠️ Ce rappel sera envoyé toutes les ${incident.priority === 'critical' ? '24' : '48'} heures jusqu'à résolution.</strong>
            </p>
        </div>

        <div class="footer">
            <p>Nexus33 VPO Analyzer - Système de suivi automatisé</p>
            <p>Cet email a été envoyé automatiquement. Ne pas répondre directement.</p>
        </div>
    </div>
</body>
</html>
        `;
    }

    getStatusLabel(status) {
        const labels = {
            'open': 'Ouvert',
            'in_progress': 'En cours',
            'pending_verification': 'Vérification en attente',
            'resolved': 'Résolu',
            'closed': 'Fermé'
        };
        return labels[status] || status;
    }

    /**
     * Envoyer un email de notification pour un nouvel incident
     */
    async sendNewIncidentNotification(incident, technicianIds) {
        const technicians = technicianIds
            .map(id => this.tracking.technicians.find(t => t.id === id))
            .filter(t => t && t.active);

        if (technicians.length === 0) return;

        const emails = technicians.map(t => t.email);
        const names = technicians.map(t => t.name).join(', ');

        const html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #0066cc; color: white; padding: 20px; border-radius: 8px 8px 0 0; }
        .content { background: #f8f9fa; padding: 20px; border: 1px solid #ddd; }
        .info-box { background: white; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .button { display: inline-block; padding: 12px 24px; background: #28a745; color: white; text-decoration: none; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2 style="margin:0;">🆕 Nouvel Incident Assigné</h2>
        </div>
        <div class="content">
            <p>Bonjour ${names},</p>
            
            <p>Un nouvel incident vous a été assigné:</p>
            
            <div class="info-box">
                <h3 style="margin-top:0;">${incident.title}</h3>
                <p><strong>ID:</strong> ${incident.id}</p>
                <p><strong>Composant:</strong> ${incident.component}</p>
                <p><strong>Priorité:</strong> ${incident.priority.toUpperCase()}</p>
                <p><strong>Date limite:</strong> ${new Date(incident.dueDate).toLocaleDateString('fr-CA')}</p>
            </div>

            ${incident.correctiveAction ? `
            <p><strong>Action Corrective Requise:</strong><br>${incident.correctiveAction}</p>
            ` : ''}

            ${incident.preventiveAction ? `
            <p><strong>Action Préventive Requise:</strong><br>${incident.preventiveAction}</p>
            ` : ''}

            <p>Merci de traiter cet incident dans les délais impartis.</p>
        </div>
    </div>
</body>
</html>
        `;

        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: emails.join(', '),
                subject: `🆕 Nouvel Incident Assigné: ${incident.id} - ${incident.title}`,
                html: html
            });
            console.log(`[EMAIL] New incident notification sent to ${names}`);
        } catch (error) {
            console.error('[EMAIL] Failed to send new incident notification:', error.message);
        }
    }

    /**
     * Envoyer un résumé quotidien
     */
    async sendDailySummary(supervisorEmail) {
        const dashboard = this.tracking.getDashboard();

        const html = `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .stat { display: inline-block; text-align: center; padding: 15px; margin: 10px; background: #f8f9fa; border-radius: 8px; min-width: 100px; }
        .stat-number { font-size: 32px; font-weight: bold; color: #0066cc; }
        .stat-label { font-size: 12px; color: #666; }
        .alert { background: #fff3cd; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .danger { background: #f8d7da; color: #721c24; }
    </style>
</head>
<body>
    <h2>📊 Résumé Quotidien - Nexus33 VPO Tracker</h2>
    <p>Date: ${new Date().toLocaleDateString('fr-CA')}</p>
    
    <div>
        <div class="stat">
            <div class="stat-number">${dashboard.byStatus.open}</div>
            <div class="stat-label">Ouverts</div>
        </div>
        <div class="stat">
            <div class="stat-number">${dashboard.byStatus.in_progress}</div>
            <div class="stat-label">En cours</div>
        </div>
        <div class="stat">
            <div class="stat-number" style="color: ${dashboard.overdue > 0 ? '#dc3545' : '#28a745'};">${dashboard.overdue}</div>
            <div class="stat-label">En retard</div>
        </div>
        <div class="stat">
            <div class="stat-number" style="color: #28a745;">${dashboard.byStatus.resolved}</div>
            <div class="stat-label">Résolus</div>
        </div>
    </div>

    ${dashboard.overdue > 0 ? `
    <div class="alert danger">
        <strong>⚠️ ${dashboard.overdue} incident(s) en retard!</strong>
        <ul>
            ${dashboard.overdueIncidents.map(i => `<li>${i.id}: ${i.title} (${i.component})</li>`).join('')}
        </ul>
    </div>
    ` : '<p>✅ Aucun incident en retard.</p>'}

    <p>Total techniciens actifs: ${dashboard.techniciansCount}</p>
</body>
</html>
        `;

        try {
            await this.transporter.sendMail({
                from: this.fromEmail,
                to: supervisorEmail,
                subject: `📊 Résumé Quotidien VPO - ${dashboard.overdue > 0 ? '⚠️ ' + dashboard.overdue + ' en retard' : '✅ Tout OK'}`,
                html: html
            });
            console.log(`[EMAIL] Daily summary sent to ${supervisorEmail}`);
        } catch (error) {
            console.error('[EMAIL] Failed to send daily summary:', error.message);
        }
    }
}

module.exports = EmailReminderService;
