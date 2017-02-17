module.exports = function (grunt) {
    // Project configuration.
    grunt.initConfig({
        pkg : grunt.file.readJSON('package.json'),
        copy : {
            build : {
                cwd : 'app',
                src : ['src/**'],
                dest : 'dest',
                expand : true
            }
        },
        clean : {
            build : {
                src : 'dest'
            }
        }
    });
    
    grunt.loadNpmTasks('grunt-contrib-copy');
    grunt.loadNpmTasks('grunt-contrib-clean');
    grunt.registerTask(
        'build',
        'Compiles all the assets and copies the files to the build directory.',
       [ 'clean', 'copy' ]
    );
};
