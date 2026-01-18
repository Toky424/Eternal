// dashboard/server.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const path = require('path');
const fs = require('fs');
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');

const app = express();

// Configuration depuis variables d'environnement
const PORT = process.env.PORT || 3000;
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_CALLBACK_URL = process.env.DISCORD_CALLBACK_URL;
const ADMIN_ROLE_ID = process.env.ADMIN_ROLE_ID;
const MOD_ROLE_ID = process.env.MOD_ROLE_ID;
const GUILD_ID = process.env.GUILD_ID;
const BOT_TOKEN = process.env.BOT_TOKEN;
const LOG_CHANNEL_ID = process.env.LOG_CHANNEL_ID;
const SESSION_SECRET = process.env.SESSION_SECRET;

// Chemins des fichiers JSON (relatifs au dossier dashboard)
const STATUS_FILE = process.env.STATUS_FILE || './status.json';
const ROSTER_FILE = process.env.ROSTER_FILE || './roster.json';
const TICKETS_FILE = process.env.TICKETS_FILE || './tickets.json';
const MOD_LOGS_FILE = process.env.MOD_LOGS_FILE || './mod_logs.json';

// Créer les fichiers JSON s'ils n'existent pas
if (!fs.existsSync(STATUS_FILE)) {
    fs.writeFileSync(STATUS_FILE, JSON.stringify({ messageId: null }));
}
if (!fs.existsSync(ROSTER_FILE)) {
    fs.writeFileSync(ROSTER_FILE, JSON.stringify({ "Equipe-Overwatch": [] }));
}
if (!fs.existsSync(TICKETS_FILE)) {
    fs.writeFileSync(TICKETS_FILE, JSON.stringify({}));
}
if (!fs.existsSync(MOD_LOGS_FILE)) {
    fs.writeFileSync(MOD_LOGS_FILE, JSON.stringify([]));
}

// Client Discord pour les actions de modération
const client = new Client({
    intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMembers,
        GatewayIntentBits.GuildBans,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.GuildPresences
    ]
});

client.login(BOT_TOKEN);

let guild;
client.on('ready', async () => {
    console.log(`Bot connecté : ${client.user.tag}`);
    guild = client.guilds.cache.get(GUILD_ID);
    console.log(`Serveur trouvé : ${guild ? guild.name : 'Non trouvé'}`);
    
    // Charger tous les membres au démarrage
    if (guild) {
        try {
            await guild.members.fetch();
            console.log(`${guild.members.cache.size} membres chargés`);
        } catch (error) {
            console.error('Erreur chargement membres:', error);
        }
    }
});

// Fonction pour envoyer un log dans le salon Discord
async function sendDiscordLog(embed) {
    if (!guild) return;
    
    try {
        const logChannel = guild.channels.cache.get(LOG_CHANNEL_ID);
        if (logChannel && logChannel.isTextBased()) {
            await logChannel.send({ embeds: [embed] });
        }
    } catch (error) {
        console.error('Erreur envoi log Discord:', error);
    }
}

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        maxAge: 24 * 60 * 60 * 1000,
        secure: process.env.NODE_ENV === 'production' // HTTPS en production
    }
}));
app.use(passport.initialize());
app.use(passport.session());

// Configuration Passport Discord
passport.use(new DiscordStrategy({
    clientID: DISCORD_CLIENT_ID,
    clientSecret: DISCORD_CLIENT_SECRET,
    callbackURL: DISCORD_CALLBACK_URL,
    scope: ['identify', 'guilds', 'guilds.members.read']
}, (accessToken, refreshToken, profile, done) => {
    profile.accessToken = accessToken;
    return done(null, profile);
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Cache pour éviter le rate limit Discord
const userRoleCache = new Map();
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

async function getUserRoles(userId, accessToken) {
    const cached = userRoleCache.get(userId);
    
    if (cached && Date.now() - cached.timestamp < CACHE_DURATION) {
        return cached.roles;
    }
    
    try {
        const response = await fetch(`https://discord.com/api/v10/users/@me/guilds/${GUILD_ID}/member`, {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        const member = await response.json();
        
        if (member.message || !member.roles) {
            console.log('Erreur API Discord:', member);
            return null;
        }
        
        userRoleCache.set(userId, {
            roles: member.roles,
            timestamp: Date.now()
        });
        
        return member.roles;
    } catch (error) {
        console.error('Erreur lors de la récupération des rôles:', error);
        return null;
    }
}

// Middleware pour vérifier si admin ou modérateur
async function isStaff(req, res, next) {
    if (!req.isAuthenticated()) {
        return res.status(401).json({ error: 'Non authentifié' });
    }

    try {
        const roles = await getUserRoles(req.user.id, req.user.accessToken);
        
        if (!roles) {
            return res.status(403).json({ error: 'Accès refusé - Impossible de vérifier les rôles' });
        }
        
        if (roles.includes(ADMIN_ROLE_ID) || roles.includes(MOD_ROLE_ID)) {
            req.userRoles = roles;
            return next();
        }
        
        return res.status(403).json({ error: 'Accès refusé - Staff requis' });
    } catch (error) {
        console.error('Erreur vérification staff:', error);
        return res.status(500).json({ error: 'Erreur de vérification' });
    }
}

// Middleware admin uniquement
function isAdmin(req, res, next) {
    if (!req.userRoles || !req.userRoles.includes(ADMIN_ROLE_ID)) {
        return res.status(403).json({ error: 'Accès refusé - Admin requis' });
    }
    next();
}

function addModLog(action, moderator, target, reason) {
    const logs = JSON.parse(fs.readFileSync(MOD_LOGS_FILE, 'utf8'));
    logs.unshift({
        id: Date.now(),
        action,
        moderator,
        target,
        reason,
        timestamp: new Date().toISOString()
    });
    if (logs.length > 100) logs.length = 100;
    fs.writeFileSync(MOD_LOGS_FILE, JSON.stringify(logs, null, 2));
}

// Routes d'authentification
app.get('/auth/discord', passport.authenticate('discord'));
app.get('/auth/discord/callback', 
    passport.authenticate('discord', { failureRedirect: '/' }),
    (req, res) => res.redirect('/dashboard')
);
app.get('/auth/logout', (req, res) => {
    req.logout(() => res.redirect('/'));
});

// Routes de l'API
app.get('/api/user', (req, res) => {
    if (!req.isAuthenticated()) {
        return res.json({ authenticated: false });
    }
    res.json({ authenticated: true, user: req.user });
});

app.get('/api/user/is-admin', isStaff, async (req, res) => {
    const isUserAdmin = req.userRoles && req.userRoles.includes(ADMIN_ROLE_ID);
    res.json({ isAdmin: isUserAdmin });
});

// Stats du bot
app.get('/api/stats', isStaff, async (req, res) => {
    const statusData = JSON.parse(fs.readFileSync(STATUS_FILE, 'utf8'));
    const rosterData = JSON.parse(fs.readFileSync(ROSTER_FILE, 'utf8'));
    const ticketsData = JSON.parse(fs.readFileSync(TICKETS_FILE, 'utf8'));
    
    let memberCount = 0;
    let onlineCount = 0;
    
    if (guild) {
        memberCount = guild.memberCount;
        
        try {
            onlineCount = guild.members.cache.filter(m => 
                m.presence && 
                m.presence.status !== 'offline' && 
                !m.user.bot
            ).size;
        } catch (error) {
            console.error('Erreur comptage membres en ligne:', error);
        }
    }
    
    res.json({
        status: statusData,
        roster: rosterData,
        ticketsCount: Object.keys(ticketsData).length,
        memberCount,
        onlineCount
    });
});

// Gestion du roster (Admin uniquement)
app.get('/api/roster', isStaff, isAdmin, (req, res) => {
    const roster = JSON.parse(fs.readFileSync(ROSTER_FILE, 'utf8'));
    res.json(roster);
});

app.post('/api/roster/add', isStaff, isAdmin, (req, res) => {
    const { team, player } = req.body;
    const roster = JSON.parse(fs.readFileSync(ROSTER_FILE, 'utf8'));
    
    if (!roster[team]) roster[team] = [];
    roster[team].push(player);
    fs.writeFileSync(ROSTER_FILE, JSON.stringify(roster, null, 2));
    
    addModLog('ROSTER_ADD', req.user.username, player.name, `Ajouté à ${team}`);
    
    const logEmbed = new EmbedBuilder()
        .setTitle('📝 Joueur Ajouté au Roster')
        .setColor('#3ba55d')
        .addFields(
            { name: 'Joueur', value: player.name, inline: true },
            { name: 'Rôle', value: player.role, inline: true },
            { name: 'Main', value: player.main, inline: true },
            { name: 'Équipe', value: team, inline: true },
            { name: 'Ajouté par', value: req.user.username, inline: true }
        )
        .setTimestamp();
    sendDiscordLog(logEmbed);
    
    res.json({ success: true, roster });
});

app.delete('/api/roster/remove', isStaff, isAdmin, (req, res) => {
    const { team, playerName } = req.body;
    const roster = JSON.parse(fs.readFileSync(ROSTER_FILE, 'utf8'));
    
    if (roster[team]) {
        roster[team] = roster[team].filter(p => p.name !== playerName);
        fs.writeFileSync(ROSTER_FILE, JSON.stringify(roster, null, 2));
    }
    
    addModLog('ROSTER_REMOVE', req.user.username, playerName, `Retiré de ${team}`);
    
    const logEmbed = new EmbedBuilder()
        .setTitle('🗑️ Joueur Retiré du Roster')
        .setColor('#ed4245')
        .addFields(
            { name: 'Joueur', value: playerName, inline: true },
            { name: 'Équipe', value: team, inline: true },
            { name: 'Retiré par', value: req.user.username, inline: true }
        )
        .setTimestamp();
    sendDiscordLog(logEmbed);
    
    res.json({ success: true, roster });
});

// Gestion des tickets
app.get('/api/tickets', isStaff, (req, res) => {
    const tickets = JSON.parse(fs.readFileSync(TICKETS_FILE, 'utf8'));
    res.json(tickets);
});

app.post('/api/tickets/close', isStaff, async (req, res) => {
    const { channelId } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const tickets = JSON.parse(fs.readFileSync(TICKETS_FILE, 'utf8'));
        const ticket = tickets[channelId];
        
        if (!ticket) {
            return res.status(404).json({ error: 'Ticket non trouvé' });
        }
        
        const channel = guild.channels.cache.get(channelId);
        if (channel) {
            await channel.delete('Ticket fermé via dashboard');
        }
        
        delete tickets[channelId];
        fs.writeFileSync(TICKETS_FILE, JSON.stringify(tickets, null, 2));
        
        addModLog('TICKET_CLOSE', req.user.username, channelId, 'Fermé via dashboard');
        
        const logEmbed = new EmbedBuilder()
            .setTitle('🎫 Ticket Fermé')
            .setColor('#ed4245')
            .addFields(
                { name: 'Ticket', value: channelId, inline: true },
                { name: 'Fermé par', value: req.user.username, inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: 'Ticket fermé' });
    } catch (error) {
        console.error('Erreur fermeture ticket:', error);
        res.status(500).json({ error: 'Erreur lors de la fermeture' });
    }
});

// Envoyer un message dans un salon
app.post('/api/message/send', isStaff, async (req, res) => {
    const { channelId, content, embed } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const channel = guild.channels.cache.get(channelId);
        if (!channel) return res.status(404).json({ error: 'Salon non trouvé' });
        
        let messageData = {};
        
        if (embed) {
            const embedObj = new EmbedBuilder()
                .setDescription(embed.description)
                .setColor(embed.color || '#5865F2');
            
            if (embed.title) embedObj.setTitle(embed.title);
            if (embed.timestamp) embedObj.setTimestamp();
            
            messageData.embeds = [embedObj];
        } else {
            messageData.content = content;
        }
        
        await channel.send(messageData);
        
        addModLog('MESSAGE_SEND', req.user.username, channel.name, embed ? embed.title || 'Embed' : 'Message simple');
        
        const logEmbed = new EmbedBuilder()
            .setTitle('💬 Message Envoyé')
            .setColor('#5865F2')
            .addFields(
                { name: 'Salon', value: `#${channel.name}`, inline: true },
                { name: 'Type', value: embed ? 'Embed' : 'Message simple', inline: true },
                { name: 'Envoyé par', value: req.user.username, inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: 'Message envoyé' });
    } catch (error) {
        console.error('Erreur envoi message:', error);
        res.status(500).json({ error: 'Erreur lors de l\'envoi' });
    }
});

// Supprimer des messages en masse
app.post('/api/message/bulk-delete', isStaff, isAdmin, async (req, res) => {
    const { channelId, count } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const channel = guild.channels.cache.get(channelId);
        if (!channel) return res.status(404).json({ error: 'Salon non trouvé' });
        
        const messages = await channel.bulkDelete(count, true);
        
        addModLog('BULK_DELETE', req.user.username, channel.name, `${messages.size} messages supprimés`);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('🗑️ Messages Supprimés')
            .setColor('#ed4245')
            .addFields(
                { name: 'Salon', value: `#${channel.name}`, inline: true },
                { name: 'Nombre', value: `${messages.size} messages`, inline: true },
                { name: 'Par', value: req.user.username, inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: `${messages.size} messages supprimés` });
    } catch (error) {
        console.error('Erreur suppression messages:', error);
        res.status(500).json({ error: 'Erreur lors de la suppression' });
    }
});

// Liste des membres
app.get('/api/members', isStaff, async (req, res) => {
    if (!guild) {
        console.log('Guild non disponible');
        return res.status(500).json({ error: 'Guild non disponible' });
    }
    
    try {
        if (guild.members.cache.size === 0) {
            console.log('Chargement des membres...');
            await guild.members.fetch();
        }
        
        const members = guild.members.cache
            .filter(m => !m.user.bot)
            .map(m => ({
                id: m.id,
                username: m.user.username,
                tag: m.user.tag,
                avatar: m.user.displayAvatarURL({ dynamic: true }),
                joinedAt: m.joinedAt,
                roles: m.roles.cache
                    .filter(r => r.id !== guild.id)
                    .map(r => ({ 
                        id: r.id, 
                        name: r.name, 
                        color: r.hexColor 
                    }))
            }))
            .sort((a, b) => a.username.localeCompare(b.username));
        
        console.log(`${members.length} membres envoyés`);
        res.json(members);
    } catch (error) {
        console.error('Erreur lors de la récupération des membres:', error);
        res.status(500).json({ error: 'Erreur lors de la récupération des membres', details: error.message });
    }
});

// Recherche de membre
app.get('/api/members/search', isStaff, async (req, res) => {
    const { query } = req.query;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        if (guild.members.cache.size === 0) {
            await guild.members.fetch();
        }
        
        const members = guild.members.cache
            .filter(m => !m.user.bot && (
                m.user.username.toLowerCase().includes(query.toLowerCase()) ||
                m.user.tag.toLowerCase().includes(query.toLowerCase())
            ))
            .map(m => ({
                id: m.id,
                username: m.user.username,
                tag: m.user.tag,
                avatar: m.user.displayAvatarURL({ dynamic: true })
            }))
            .slice(0, 10);
        
        res.json(members);
    } catch (error) {
        console.error('Erreur de recherche:', error);
        res.status(500).json({ error: 'Erreur de recherche' });
    }
});

// Actions de modération - KICK (Admin uniquement)
app.post('/api/moderation/kick', isStaff, isAdmin, async (req, res) => {
    const { userId, reason } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const member = await guild.members.fetch(userId);
        if (!member.kickable) {
            return res.status(400).json({ error: 'Impossible de kick ce membre' });
        }
        
        await member.kick(reason);
        addModLog('KICK', req.user.username, member.user.tag, reason);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('🔨 Membre Expulsé')
            .setColor('#faa61a')
            .addFields(
                { name: 'Membre', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true },
                { name: 'Raison', value: reason || 'Aucune raison fournie', inline: false }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: `${member.user.tag} a été expulsé` });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du kick' });
    }
});

// BAN (Admin uniquement)
app.post('/api/moderation/ban', isStaff, isAdmin, async (req, res) => {
    const { userId, reason, deleteMessages } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const member = await guild.members.fetch(userId);
        if (!member.bannable) {
            return res.status(400).json({ error: 'Impossible de ban ce membre' });
        }
        
        await member.ban({ 
            reason, 
            deleteMessageSeconds: deleteMessages ? 604800 : 0
        });
        addModLog('BAN', req.user.username, member.user.tag, reason);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('🚫 Membre Banni')
            .setColor('#ed4245')
            .addFields(
                { name: 'Membre', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true },
                { name: 'Raison', value: reason || 'Aucune raison fournie', inline: false },
                { name: 'Messages supprimés', value: deleteMessages ? 'Oui (7 jours)' : 'Non', inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: `${member.user.tag} a été banni` });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du ban' });
    }
});

// UNBAN (Admin uniquement)
app.post('/api/moderation/unban', isStaff, isAdmin, async (req, res) => {
    const { userId, reason } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        await guild.bans.remove(userId, reason);
        addModLog('UNBAN', req.user.username, userId, reason);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('✅ Membre Débanni')
            .setColor('#3ba55d')
            .addFields(
                { name: 'User ID', value: userId, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true },
                { name: 'Raison', value: reason || 'Aucune raison fournie', inline: false }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: 'Membre débanni' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du unban' });
    }
});

// TIMEOUT (Modérateurs et Admins)
app.post('/api/moderation/timeout', isStaff, async (req, res) => {
    const { userId, duration, reason } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const member = await guild.members.fetch(userId);
        await member.timeout(duration * 60 * 1000, reason);
        addModLog('TIMEOUT', req.user.username, member.user.tag, `${duration}min - ${reason}`);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('⏱️ Membre en Timeout')
            .setColor('#5865F2')
            .addFields(
                { name: 'Membre', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true },
                { name: 'Durée', value: `${duration} minutes`, inline: true },
                { name: 'Raison', value: reason || 'Aucune raison fournie', inline: false }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: `${member.user.tag} en timeout pour ${duration} minutes` });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du timeout' });
    }
});

// REMOVE TIMEOUT (Modérateurs et Admins)
app.post('/api/moderation/remove-timeout', isStaff, async (req, res) => {
    const { userId } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const member = await guild.members.fetch(userId);
        await member.timeout(null);
        addModLog('REMOVE_TIMEOUT', req.user.username, member.user.tag, 'Timeout retiré');
        
        const logEmbed = new EmbedBuilder()
            .setTitle('✅ Timeout Retiré')
            .setColor('#3ba55d')
            .addFields(
                { name: 'Membre', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: 'Timeout retiré' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur' });
    }
});

// Gestion des rôles
app.get('/api/roles', isStaff, async (req, res) => {
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    const roles = guild.roles.cache
        .filter(r => r.id !== guild.id)
        .map(r => ({
            id: r.id,
            name: r.name,
            color: r.hexColor,
            position: r.position
        }))
        .sort((a, b) => b.position - a.position);
    
    res.json(roles);
});

// Ajouter un rôle à un membre (Admin uniquement)
app.post('/api/moderation/add-role', isStaff, isAdmin, async (req, res) => {
    const { userId, roleId } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const member = await guild.members.fetch(userId);
        const role = guild.roles.cache.get(roleId);
        
        await member.roles.add(role);
        addModLog('ROLE_ADD', req.user.username, member.user.tag, `Rôle ${role.name} ajouté`);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('➕ Rôle Ajouté')
            .setColor('#3ba55d')
            .addFields(
                { name: 'Membre', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Rôle', value: role.name, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: `Rôle ${role.name} ajouté à ${member.user.tag}` });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'ajout du rôle' });
    }
});

// Retirer un rôle (Admin uniquement)
app.post('/api/moderation/remove-role', isStaff, isAdmin, async (req, res) => {
    const { userId, roleId } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const member = await guild.members.fetch(userId);
        const role = guild.roles.cache.get(roleId);
        
        await member.roles.remove(role);
        addModLog('ROLE_REMOVE', req.user.username, member.user.tag, `Rôle ${role.name} retiré`);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('➖ Rôle Retiré')
            .setColor('#faa61a')
            .addFields(
                { name: 'Membre', value: `${member.user.tag} (${member.id})`, inline: true },
                { name: 'Rôle', value: role.name, inline: true },
                { name: 'Modérateur', value: req.user.username, inline: true }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: `Rôle ${role.name} retiré de ${member.user.tag}` });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors du retrait du rôle' });
    }
});

// Liste des bans
app.get('/api/moderation/bans', isStaff, async (req, res) => {
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const bans = await guild.bans.fetch();
        const banList = bans.map(ban => ({
            userId: ban.user.id,
            username: ban.user.username,
            tag: ban.user.tag,
            reason: ban.reason
        }));
        
        res.json(banList);
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de la récupération des bans' });
    }
});

// Logs de modération
app.get('/api/moderation/logs', isStaff, (req, res) => {
    const logs = JSON.parse(fs.readFileSync(MOD_LOGS_FILE, 'utf8'));
    res.json(logs.slice(0, 50));
});

// Envoi d'annonce (Admin uniquement)
app.post('/api/announcement', isStaff, isAdmin, async (req, res) => {
    const { channelId, title, message, color } = req.body;
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    try {
        const channel = guild.channels.cache.get(channelId);
        if (!channel) return res.status(404).json({ error: 'Salon non trouvé' });
        
        const embed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(message)
            .setColor(color || '#5865F2')
            .setTimestamp()
            .setFooter({ text: `Annonce par ${req.user.username}` });
        
        await channel.send({ embeds: [embed] });
        addModLog('ANNOUNCEMENT', req.user.username, channel.name, title);
        
        const logEmbed = new EmbedBuilder()
            .setTitle('📢 Annonce Envoyée')
            .setColor('#5865F2')
            .addFields(
                { name: 'Salon', value: `#${channel.name}`, inline: true },
                { name: 'Titre', value: title, inline: true },
                { name: 'Envoyée par', value: req.user.username, inline: true },
                { name: 'Message', value: message.substring(0, 1000), inline: false }
            )
            .setTimestamp();
        await sendDiscordLog(logEmbed);
        
        res.json({ success: true, message: 'Annonce envoyée' });
    } catch (error) {
        res.status(500).json({ error: 'Erreur lors de l\'envoi' });
    }
});

// Liste des salons
app.get('/api/channels', isStaff, async (req, res) => {
    if (!guild) return res.status(500).json({ error: 'Guild non disponible' });
    
    const channels = guild.channels.cache
        .filter(c => c.isTextBased())
        .map(c => ({
            id: c.id,
            name: c.name,
            type: c.type
        }));
    
    res.json(channels);
});

// Pages
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/dashboard', async (req, res) => {
    if (!req.isAuthenticated()) {
        return res.redirect('/');
    }
    
    try {
        const roles = await getUserRoles(req.user.id, req.user.accessToken);
        
        if (roles && (roles.includes(ADMIN_ROLE_ID) || roles.includes(MOD_ROLE_ID))) {
            res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
        } else {
            res.status(403).send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Accès Refusé</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            display: flex;
                            justify-content: center;
                            align-items: center;
                            height: 100vh;
                            margin: 0;
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        }
                        .error-box {
                            background: white;
                            padding: 40px;
                            border-radius: 10px;
                            text-align: center;
                            box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                        }
                        h1 { color: #ed4245; }
                        p { color: #666; }
                        a {
                            display: inline-block;
                            margin-top: 20px;
                            padding: 10px 20px;
                            background: #5865F2;
                            color: white;
                            text-decoration: none;
                            border-radius: 5px;
                        }
                    </style>
                </head>
                <body>
                    <div class="error-box">
                        <h1>🚫 Accès Refusé</h1>
                        <p>Vous devez être <strong>Administrateur</strong> ou <strong>Modérateur</strong> pour accéder au dashboard.</p>
                        <a href="/auth/logout">Se déconnecter</a>
                    </div>
                </body>
                </html>
            `);
        }
    } catch (err) {
        console.error('Erreur vérification:', err);
        res.redirect('/');
    }
});

app.listen(PORT, () => {
    console.log(`✅ Dashboard accessible sur http://localhost:${PORT}`);
    console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
});