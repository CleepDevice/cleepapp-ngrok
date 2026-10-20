/**
 * Ngrok config component
 * Handle ngrok application configuration
 */
angular
.module('Cleep')
.directive('ngrokConfigComponent', ['cleepService', 'toastService', 'ngrokService', '$location',
function(cleepService, toastService, ngrokService, $location) {

    const ngrokConfigController = function($scope) {
        const self = this;
        self.config = {};
        self.serviceButtons = [];
        self.authButtons = [];
        self.authSubtitle = '';
        self.publicUrl = '';
        self.agentStatus = '';
        self.infoColumns = [
            { id: 'id', label: 'Id' },
            { id: 'publicurl', label: 'Public URL' },
            { id: 'proto', label: 'Protocol' },
        ];
        self.infoRows = [];
        self.connectionsColumns = [
            { id: 'tunnel', label: 'Tunnel' },
            { id: 'total', label: 'Total' },
            { id: 'rate1', label: '/sec 1m' },
            { id: 'rate5', label: '/sec 5m' },
            { id: 'rate15', label: '/sec 15m' },
        ];
        self.connectionsRows = [];
        self.durationsColumns = [
            { id: 'tunnel', label: 'Tunnel' },
            { id: 'p50', label: '50%' },
            { id: 'p90', label: '90%' },
            { id: 'p95', label: '95%' },
            { id: 'p99', label: '99%' },
        ];
        self.durationsRows = [];

        self.$onInit = function() {
            cleepService.reloadModuleConfig('ngrok');
            cleepService.reloadModuleConfig('parameters');

            self.serviceButtons.push({
                icon: 'play',
                tooltip: 'Start tunnel',
                click: self.startTunnel,
            });
            self.serviceButtons.push({
                icon: 'stop',
                tooltip: 'Stop tunnel',
                click: self.stopTunnel,
            });
        };

        self.escapeHtml = function(value) {
            return String(value)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        };

        self.setAuthKey = function (value) {
            ngrokService.setAuthKey(value)
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Auth key saved, you can start tunnel');
                    }
                });
        };

        self.setAutoStart = function (value) {
            ngrokService.setAutoStart(value)
                .then((resp) => {
                    if (!resp.error) {
                        const mode = value ? 'enabled' : 'disabled';
                        toastService.success(`Auto start ${mode}`);
                    }
                });
        };

        self.metricRow = function(tunnel, metrics, fields) {
            const row = { tunnel: tunnel };
            fields.forEach((field) => {
                row[field.id] = metrics?.[field.src] ?? '';
            });
            return row;
        };

        self.applyTunnelInfo = function(data) {
            self.infoRows = [{
                id: data.id || '',
                publicurl: data.publicurl || '',
                proto: data.proto || '',
            }];

            const metrics = data.metrics || {};
            const hasMetrics = metrics.conns || metrics.http;
            if (!hasMetrics) {
                self.connectionsRows = [];
                self.durationsRows = [];
                return;
            }

            self.connectionsRows = [
                self.metricRow('agent', metrics.conns, [
                    { id: 'total', src: 'count' },
                    { id: 'rate1', src: 'rate1' },
                    { id: 'rate5', src: 'rate5' },
                    { id: 'rate15', src: 'rate15' },
                ]),
                self.metricRow('http', metrics.http, [
                    { id: 'total', src: 'count' },
                    { id: 'rate1', src: 'rate1' },
                    { id: 'rate5', src: 'rate5' },
                    { id: 'rate15', src: 'rate15' },
                ]),
            ];
            self.durationsRows = [
                self.metricRow('agent', metrics.conns, [
                    { id: 'p50', src: 'p50' },
                    { id: 'p90', src: 'p90' },
                    { id: 'p95', src: 'p95' },
                    { id: 'p99', src: 'p99' },
                ]),
                self.metricRow('http', metrics.http, [
                    { id: 'p50', src: 'p50' },
                    { id: 'p90', src: 'p90' },
                    { id: 'p95', src: 'p95' },
                    { id: 'p99', src: 'p99' },
                ]),
            ];
        };

        self.getTunnelInfo = function () {
            ngrokService.getTunnelInfo()
                .then((resp) => {
                    if (resp.error || !resp.data) {
                        return;
                    }
                    self.applyTunnelInfo(resp.data);
                });
        };

        self.startTunnel = function () {
            toastService.loading('Launching tunnel');
            ngrokService.startTunnel()
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Tunnel started');
                    }
                });
        };

        self.stopTunnel = function () {
            ngrokService.stopTunnel()
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Tunnel stopped');
                    }
                });
        };

        self.setPublicUrl = function(statusOrUrl) {
            const labels = {
                STOPPED: 'Tunnel is stopped',
                STARTED: 'Tunnel is started',
                STARTING: 'Tunnel is starting',
                ERROR: 'Error with tunnel',
            };

            if (!statusOrUrl) {
                self.publicUrl = labels.STOPPED;
                return;
            }

            const value = String(statusOrUrl);
            if (/^https?:\/\//i.test(value)) {
                const safeUrl = self.escapeHtml(value);
                self.publicUrl = `<a href="${safeUrl}" target="_blank" rel="noopener">${safeUrl}</a>`;
                return;
            }

            self.publicUrl = labels[value] || self.escapeHtml(value);
        };

        self.openAuthSettings = function() {
            $location.url('/module/parameters?tab=auth');
        };

        self.updateAuthState = function(ready) {
            const enabled = !!ready;
            self.authSubtitle = enabled
                ? 'Secured access is enabled'
                : 'Enable secured access before opening a tunnel';
            const buttons = [{
                label: enabled ? 'Enabled' : 'Disabled',
                icon: enabled ? 'shield-check' : 'shield-off',
                disabled: true,
                click: angular.noop,
            }];
            if (!enabled) {
                buttons.push({
                    label: 'Configure',
                    icon: 'cog',
                    tooltip: 'Open secured access settings',
                    click: self.openAuthSettings,
                });
            }
            self.authButtons = buttons;
        };

        self.setAgentStatus = function(agentError, agentRunning) {
            if (agentError) {
                self.agentStatus = self.escapeHtml(agentError).replace(/(\r\n|\n|\\r\\n|\\n)/g, '<br/>');
                return;
            }
            self.agentStatus = agentRunning ? 'Agent is running' : 'Agent is stopped';
        };

        self.updateBinary = function() {
            ngrokService.updateBinary()
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Ngrok service binary will be updated if necessary');
                    }
                });
        };

        $scope.$watch(
            () => cleepService.modules.ngrok && cleepService.modules.ngrok.config,
            (newConfig) => {
                if (newConfig && Object.keys(newConfig).length) {
                    Object.assign(self.config, newConfig);
                    self.setPublicUrl(self.config.publicurl || self.config.tunnelstatus);
                    self.setAgentStatus(self.config.agenterror, self.config.agentrunning);
                }
            },
            true
        );

        $scope.$watch(
            () => cleepService.modules.parameters && cleepService.modules.parameters.config,
            (config) => {
                if (!config) {
                    self.updateAuthState(!!self.config.cleepauth);
                    return;
                }
                const accounts = Array.isArray(config.authaccounts) ? config.authaccounts : [];
                self.updateAuthState(!!config.authenabled && accounts.length > 0);
            },
            true
        );

        $scope.$on('ngrok.tunnel.update', (event, uuid, params) => {
            if (!params) {
                return;
            }
            if (params.publicurl) {
                self.config.publicurl = params.publicurl;
            }
            if (params.status) {
                self.config.tunnelstatus = params.status;
                if (params.status === 'STOPPED' || params.status === 'ERROR') {
                    self.config.publicurl = params.publicurl || null;
                }
            }
            self.setPublicUrl(params.publicurl || params.status);
        });
    };

    return {
        templateUrl: 'ngrok.config.html',
        replace: true,
        scope: true,
        controller: ngrokConfigController,
        controllerAs: '$ctrl',
    };
}]);
