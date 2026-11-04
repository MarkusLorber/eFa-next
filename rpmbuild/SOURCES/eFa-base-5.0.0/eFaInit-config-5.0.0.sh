#!/bin/sh
#-----------------------------------------------------------------------------#
# eFa 5.0.0 initial service-configuration script
#-----------------------------------------------------------------------------#
# Copyright (C) 2024 https://efa-project.org
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# Source the settings file
#-----------------------------------------------------------------------------#
source /usr/src/eFa/eFa-settings.inc
#-----------------------------------------------------------------------------#

#-----------------------------------------------------------------------------#
# Start configuration of services
#-----------------------------------------------------------------------------#

# Copy eFa-Init into apache
echo "Configuring eFaInit..."

# Grant apache permissions to cache/log
systemctl enable efa-init

cat > /usr/sbin/checkreboot.sh << 'EOF'
#!/bin/bash
if [[ -f /reboot.system ]]; then
  rm -f /reboot.system
  /sbin/shutdown -r now
fi
EOF
chmod +x /usr/sbin/checkreboot.sh

echo '* * * * * root /usr/sbin/checkreboot.sh' > /etc/cron.d/checkreboot

# Allow apache to sudo for eFaInit phase
# The wizard may only run the commit step, and only until it has finished.
echo 'efa-web ALL=(root) NOPASSWD: /usr/sbin/eFa-Commit' > /etc/sudoers.d/efa-init
chmod 440 /etc/sudoers.d/efa-init

echo "Configuring eFaInit...done"
