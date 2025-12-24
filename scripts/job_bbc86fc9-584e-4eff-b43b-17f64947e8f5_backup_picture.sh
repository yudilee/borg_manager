#!/bin/bash
# Borg Backup Job: backup_picture
# ID: bbc86fc9-584e-4eff-b43b-17f64947e8f5

echo "Starting Backup: $(date)" >> /home/yudi/.config/borg-gui/logs/job_bbc86fc9-584e-4eff-b43b-17f64947e8f5_cron.log

# Environment Variables
export BORG_REPO='ssh://backupuser@10.101.24.71/home/backupuser/backup_88'
export BORG_PASSPHRASE='Gul-5832'
export SSHPASS='Gul-5832'
export BORG_RSH='sshpass -e ssh -o StrictHostKeyChecking=accept-new'
export BORG_RELOCATED_REPO_ACCESS_IS_OK=no

# Run Backup
None create --stats --compression zstd,6 --exclude '/home/yudi/Pictures/Screenshots' ::backup_picture-$(date +%Y-%m-%d-%H%M) '/home/yudi/Pictures' >> /home/yudi/.config/borg-gui/logs/job_bbc86fc9-584e-4eff-b43b-17f64947e8f5_cron.log 2>&1

if [ $? -eq 0 ]; then
    echo "Backup Success: $(date)" >> /home/yudi/.config/borg-gui/logs/job_bbc86fc9-584e-4eff-b43b-17f64947e8f5_cron.log
    # Run Prune
    echo "Starting Prune..." >> /home/yudi/.config/borg-gui/logs/job_bbc86fc9-584e-4eff-b43b-17f64947e8f5_cron.log
    None prune --list --stats --keep-daily 7 --keep-weekly 4 --keep-monthly 6 >> /home/yudi/.config/borg-gui/logs/job_bbc86fc9-584e-4eff-b43b-17f64947e8f5_cron.log 2>&1
else
    echo "Backup Failed: $(date)" >> /home/yudi/.config/borg-gui/logs/job_bbc86fc9-584e-4eff-b43b-17f64947e8f5_cron.log
fi