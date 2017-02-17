module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        'closure-compiler': {
            security: {
                closurePath  : '/home/pyknic/closure_compiler',
                js           : 'src/security.js',
                jsOutputFile : 'bin/security.min.js',
                maxBuffer    : 500,
                options      : {
                    compilation_level : 'ADVANCED_OPTIMIZATIONS',
                    language_in       : 'ECMASCRIPT5_STRICT'
                }
            }
        }
    });
    
    grunt.loadNpmTasks('grunt-closure-compiler');
};