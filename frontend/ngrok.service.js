/**
 * Ngrok service.
 * Handle ngrok application requests.
 */
angular
.module('Cleep')
.service('ngrokService', ['rpcService', 'cleepService', 
function(rpcService, cleepService) {
    const self = this;

    self.setAuthKey = function (authKey) {
        const data = {
            auth_key: authKey,
        }
        return rpcService.sendCommand('set_auth_key', 'ngrok', data)
            .then(() => cleepService.reloadModuleConfig('ngrok'));
    };

    self.setAutoStart = function (autoStart) {
        const data = {
            auto_start: autoStart,
        }
        return rpcService.sendCommand('set_auto_start', 'ngrok', data)
            .then(() => cleepService.reloadModuleConfig('ngrok'));
    };

    self.getTunnelInfo = function () {
        return rpcService.sendCommand('get_tunnel_info', 'ngrok');
    };

    self.startTunnel = function () {
        return rpcService.sendCommand('start_tunnel', 'ngrok')
            .then(() => cleepService.reloadModuleConfig('ngrok'));
    }

    self.stopTunnel = function () {
        return rpcService.sendCommand('stop_tunnel', 'ngrok')
            .then(() => cleepService.reloadModuleConfig('ngrok'));
    }
}]);
