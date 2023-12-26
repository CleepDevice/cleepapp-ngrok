/**
 * Ngrok config component
 * Handle ngrok application configuration
 * If your application doesn't need configuration page, delete this file and its references into desc.json
 */
angular
.module('Cleep')
.directive('ngrokConfigComponent', ['$rootScope', 'cleepService', 'toastService', 'ngrokService',
function($rootScope, cleepService, toastService, ngrokService) {

    var ngrokConfigController = function($scope) {
        var self = this;
        self.config = {};
        self.serviceButtons = [];
        self.publicUrl = '';
        self.metrics = {
            connections: 'No metrics',
            durations: 'No metrics',
        };

        self.$onInit = function() {
            cleepService.getModuleConfig('ngrok');

            self.serviceButtons.push({
                icon: 'play',
                tooltip: 'Start tunnel',
                click: ngrokService.startTunnel,
            });
            self.serviceButtons.push({
                icon: 'stop',
                tooltip: 'Stop tunnel',
                click: ngrokService.stopTunnel,
            });
        };

        self.setAuthKey = function (value) {
            ngrokService.setAuthKey(value)
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Auth key saved');
                    }
                });
        }

        self.setAutoStart = function (value) {
            ngrokService.setAutoStart(value)
                .then((resp) => {
                    if (!resp.error) {
                        const mode = value ? 'enabled' : 'disabled';
                        toastService.success(`Auto start ${mode}`);
                    }
                });
        }

        self.tunnelInfoToMarkdown = function(metrics) {
            const connections = [];
            const durations = [];

            if (metrics.conns || metrics.http) {
                connections.push('| tunnel | total | /sec 1m | /sec 5m | /sec 15m |');
                connections.push('| ----- | ----- | ----- | ----- | ----- |');
                connections.push(`| agent | ${metrics.conns?.count} | ${metrics.conns?.rate1} | ${metrics.conns?.rate5} | ${metrics.conns?.rate15} |`);
                connections.push(`| http | ${metrics.http?.count} | ${metrics.http?.rate1} | ${metrics.http?.rate5} | ${metrics.http?.rate15} |`);

                durations.push('| tunnel | 50% | 90% | 95% | 99% |');
                durations.push('| ----- | ----- | ----- | ----- | ----- |');
                durations.push(`| agent | ${metrics.conns?.p50} | ${metrics.conns?.p90} | ${metrics.conns?.p95} | ${metrics.conns?.p99} |`);
                durations.push(`| http | ${metrics.http?.p50} | ${metrics.http?.p90} | ${metrics.http?.p95} | ${metrics.http?.p99} |`);
            }

            return {
                connections: connections.join('\n'),
                durations: durations.join('\n')
            };
        }

        self.getTunnelInfo = function () {
            ngrokService.getTunnelInfo()
                .then((resp) => {
                    if (!resp.error) {
                        self.metrics = self.tunnelInfoToMarkdown(resp.data.metrics);
                    }
                });
        }

        self.startTunnel = function () {
            ngrokService.startTunnel()
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Tunnel started')
                    }
                });
        }

        self.stopTunnel = function () {
            ngrokService.stopTunnel()
                .then((resp) => {
                    if (!resp.error) {
                        toastService.success('Tunnel stopped')
                    }
                });
        }

        self.setPublicUrl = function(statusOrUrl) {
            const isUrl = statusOrUrl.startsWith('http');
            if (isUrl) {
                self.publicUrl = `<a href="${self.config.publicurl}" target="_blank">${self.config.publicurl}</a>`;
            } else if (statusOrUrl === 'STOPPED') {
                self.publicUrl = 'Tunnel is stopped';
            } else if (statusOrUrl === 'STARTED') {
                self.publicUrl = 'Tunnel is started';
            } else if (statusOrUrl === 'STARTING') {
                self.publicUrl = 'Tunnel is starting';
            } else if (statusOrUrl === 'ERROR') {
                self.publicUrl = 'Error with tunnel';
            } else {
                self.publicUrl = statusOrUrl;
            }
        }

        $rootScope.$watch(function() {
            return cleepService.modules['ngrok'].config;
        }, function(newConfig) {
            if(newConfig && Object.keys(newConfig).length) {
                Object.assign(self.config, newConfig);
                self.setPublicUrl(self.config.publicurl || self.config.tunnelstatus);
            }
        }, true);

        $rootScope.$on('ngrok.tunnel.update', (event, uuid, params) => {
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
