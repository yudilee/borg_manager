#!/bin/bash
# Borg Backup Job: backup_music
# ID: fd460005-ecbf-4a32-adb5-e65cccb59626

echo "Starting Backup: $(date)" >> /home/yudi/dev/borg_manager/logs/job_fd460005-ecbf-4a32-adb5-e65cccb59626_cron.log

# Environment Variables
export BORG_REPO='ssh://backupuser@10.101.24.71/home/backupuser/backup_88'
export BORG_PASSPHRASE='Gul-5832'
export SSHPASS='Gul-5832'
export BORG_RSH='sshpass -e ssh -o StrictHostKeyChecking=accept-new'
export BORG_RELOCATED_REPO_ACCESS_IS_OK=no

# Run Backup
None create --stats --compression zstd,6 --exclude '/home/yudi/Music/HRM_MSV.zip' --exclude '/home/yudi/Music/HRM_MSV' --exclude '/home/yudi/Music/audiobook' --exclude '/home/yudi/Music/Libation' ::backup_music-$(date +%Y-%m-%d-%H%M) '/home/yudi/Music' >> /home/yudi/dev/borg_manager/logs/job_fd460005-ecbf-4a32-adb5-e65cccb59626_cron.log 2>&1

if [ $? -eq 0 ]; then
    echo "Backup Success: $(date)" >> /home/yudi/dev/borg_manager/logs/job_fd460005-ecbf-4a32-adb5-e65cccb59626_cron.log
    # Run Prune
    echo "Starting Prune..." >> /home/yudi/dev/borg_manager/logs/job_fd460005-ecbf-4a32-adb5-e65cccb59626_cron.log
    None prune --list --stats --keep-daily 7 --keep-weekly 4 --keep-monthly 6 >> /home/yudi/dev/borg_manager/logs/job_fd460005-ecbf-4a32-adb5-e65cccb59626_cron.log 2>&1
else
    echo "Backup Failed: $(date)" >> /home/yudi/dev/borg_manager/logs/job_fd460005-ecbf-4a32-adb5-e65cccb59626_cron.log
fi