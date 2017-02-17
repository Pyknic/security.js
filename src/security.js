/**
 * Copyright 2017 Emil Forslund
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not 
 * use this file except in compliance with the License. You may obtain a copy of 
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT 
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the 
 * License for the specific language governing permissions and limitations under 
 * the License.
 */

/**
 * Declares the 'Security' module.
 * 
 * @param {object} window  the dom window
 * @returns {undefined}
 */
(function(window) {
    'use strict';
    
    if (typeof(window.Security) === 'undefined') {
        
        ////////////////////////////////////////////////////////////////////////
        //                            Dependencies                            //
        ////////////////////////////////////////////////////////////////////////
        
        var bcrypt = require('bcryptjs');
        
        ////////////////////////////////////////////////////////////////////////
        //                           Internal methods                         //
        ////////////////////////////////////////////////////////////////////////
        
        /**
         * Takes a parameter and if it is a valid string, returns it. Otherwise,
         * an exception is thrown.
         * 
         * @param {type} s    the value to check
         * @returns {number}  the value inputted
         */
        var expectString = function(s) {
            if (typeof(s) === 'string') {
                return s;
            } else {
                throw 'Specified value "' + s + '" is not a string.';
            }
        };

        /**
         * Takes a parameter and if it is a valid number, returns it. Otherwise,
         * an exception is thrown.
         * 
         * @param {type} n    the value to check
         * @returns {number}  the value inputted
         */
        var expectNumber = function(n) {
            if (typeof(n) === 'number') {
                return n;
            } else {
                throw 'Specified value "' + n + '" is not a number.';
            }
        };
        
        /**
         * Takes a parameter and if it is a valid function, returns it. 
         * Otherwise, an exception is thrown.
         * 
         * @param {type} f      the value to check
         * @returns {function}  the value inputted
         */
        var expectFunction = function(f) {
            if (typeof(f) === 'function') {
                return f;
            } else {
                throw 'Specified value "' + f + '" is not a function.';
            }
        };

        /**
         * If the first parameter is a valid function, return it. If it is
         * undefined, return the second parameter. If the first parameter is of
         * an unknown type (not a function or undefined), throw an exception.
         * 
         * @param {type} f          the value to check
         * @param {type} otherwise  value to return if f is undefined
         * @returns {function}      either 'f' (if a function) or 'otherwise'
         */
        var functionOr = function(f, otherwise) {
            if (typeof(f) === 'function') {
                return f;
            } else if (typeof(f) === 'undefined') {
                return otherwise;
            } else {
                throw 'Expected function, but got "' + typeof(f) + '".';
            }
        };
        
        /**
         * If the first parameter is a valid boolean, return it. If it is
         * undefined, return the second parameter. If the first parameter is of
         * an unknown type (not a boolean or undefined), throw an exception.
         * 
         * @param {type} b          the value to check
         * @param {type} otherwise  value to return if f is undefined
         * @returns {boolean}      either 'b' (if a boolean) or 'otherwise'
         */
        var booleanOr = function(b, otherwise) {
            if (typeof(b) === 'boolean') {
                return b;
            } else if (typeof(b) === 'undefined') {
                return otherwise;
            } else {
                throw 'Expected boolean, but got "' + typeof(b) + '".';
            }
        };
        
        
        ////////////////////////////////////////////////////////////////////////
        //                           Internal classes                         //
        ////////////////////////////////////////////////////////////////////////
        
        /**
         * Holds information about a login attempt. If the attempts succeeds,
         * the 'onSuccess' handler will be invoked with the response from the
         * server. If not, the 'onFailure' handler will be invoked with the
         * reponse body.
         * <p>
         * If the 'remember' value is set, the credentials will be stored for
         * future use in the local storage.
         * 
         * @argument {string} username  the username to login with 
         * @argument {string} password  the unhashed password to login with
         * @argument {boolean} remember true to store credentials, else false
         * 
         * @returns {securityL#23.LoginSpec}  the constructed instance
         */
        var LoginSpec = function(username, password, remember) {
            this.username  = expectString(username);
            this.password  = expectString(password);
            this.remember  = booleanOr(remember, false);
            
            this.success = function(res) {
                console.log('Login success! Response: ' + res);
            };
            
            this.failure = function(res, status) {
                console.error('Login failed with status ' + status + 
                    '! Response: ' + res);
            };
        };
        
        /**
         * Modified the success handler to be the specified handler function.
         * <p>
         * The given function should take the data returned from the server as
         * its first parameter and the status code of the login request as the
         * second. Both parameters are optional.
         * 
         * @argument {function(object, number)} handler  the new success handler
         * @returns {securityL#23.LoginSpec}             this instance
         */
        LoginSpec.prototype.onSuccess = function(handler) {
            this.success = expectFunction(handler);
            return this;
        };
        
        /**
         * Modified the failure handler to be the specified handler function.
         * <p>
         * The given function should take the data returned from the server as
         * its first parameter and the status code of the login request as the
         * second. Both parameters are optional.
         * 
         * @argument {function(object, number)} handler  the new failure handler
         * @returns {securityL#23.LoginSpec}             this instance
         */
        LoginSpec.prototype.onFailure = function(handler) {
            this.failure = expectFunction(handler);
            return this;
        };
        
        ////////////////////////////////////////////////////////////////////////
        //                              Constructor                           //
        ////////////////////////////////////////////////////////////////////////
        
        /**
         * The 'Security' namespace. These methods are part of the public API.
         */
        window.Security = {
            
            ////////////////////////////////////////////////////////////////////
            //                         Member Variables                       //
            ////////////////////////////////////////////////////////////////////
            username : null,
            password : null,

            ////////////////////////////////////////////////////////////////////
            //                        Manage Credentials                      //
            ////////////////////////////////////////////////////////////////////

            /**
             * Returns the username of the currently logged in user, or throws
             * an exception if the user is not logged in.
             * 
             * @returns {string}  the username
             */
            getUsername : function() {
                return this.username;
            },

            /**
             * Returns the encrypted password of the currently logged in user, 
             * or throws an exception if the user is not logged in.
             * 
             * @returns {string}  the password
             */
            getPassword : function() {
                return this.password;
            },
            
            /**
             * Returns a boolean to indicate if the user is logged in or not.
             * 
             * @returns {boolean}  true if logged in, else false
             */
            isLoggedIn : function() {
                return this.username !== null
                    && this.password !== null;
            },
            
            /**
             * Starts the login service, loading any stored credentials from
             * either the local session or the local storage if available. If
             * not, start the login service logged out.
             * 
             * @returns {Security}  this instance
             */
            start : function() {
                if (typeof(localStorage.user) === 'string'
                &&  typeof(localStorage.pass) === 'string') {
                    return this.loadStored();
                    
                } else if (typeof(sessionStorage.user) === 'string'
                &&         typeof(sessionStorage.pass) === 'string') {
                   return this.loadSession();
                   
                } else {
                    return this;
                }
            },

            /**
             * Login using the specified credentials, storing them in either the
             * local session or local storage depending on the 'remember'
             * parameter. To logout again, use the .logout()-method.
             * <p>
             * The method will make an asynchronous request to the specified url
             * with the Basic Authentication header set to the username and
             * password specified in the 'config' object. The password will be
             * hashed using a 10 pass bcrypt. If the request succeeds, then the
             * credentials will be stored either in the session or the local
             * storage before the success handler is called. If it fails, the
             * failure handler will be called.
             * 
             * @param {string} url        the url of the remote login service
             * @param {LoginSpec} config  the credentials and handlers
             * @returns {Security}        this instance
             */
            login : function(url, config) {
                
                expectString(url);
                expectString(config.username);
                expectString(config.password);
                expectFunction(config.success);
                expectFunction(config.failure);
                
                bcrypt.hash(config.password, 10, function(err, hash) {
                    if (err !== null) {
                        throw err;
                    } else {
                        expectString(hash);
                        
                        var xhttp = new XMLHttpRequest();
                        xhttp.open('GET', url, true);
                        xhttp.onreadystatechange = function() {
                            if (this.readyState === 4) {
                                var res    = JSON.parse(xhttp.responseText);
                                var status = expectNumber(xhttp.status);
                                
                                if (status === 200) {
                                    this.user = config.username;
                                    this.pass = hash;

                                    if (config.remember) {
                                        localStorage.user = this.user;
                                        localStorage.pass = this.pass;
                                    } else {
                                        sessionStorage.user = this.user;
                                        sessionStorage.pass = this.pass;
                                    }
                                    
                                    config.success(res, status);
                                } else {
                                    config.failure(res, status);
                                }
                            }
                        };

                        xhttp.withCredentials = true;
                        xhttp.setRequestHeader('Authorization', 'Basic ' + 
                            btoa(config.username + ':' + hash));
                    }
                });
                
                return this;
            },

            /**
             * Load credentials from the local storage, throwing an exception if
             * they are not present.
             * 
             * @returns {Security}  this instance
             */
            loadStored : function() {
                console.log("Logged in using stored credentials.");
                this.username = expectString(localStorage.user);
                this.password = expectString(localStorage.pass);
                return this;
            },
            
            /**
             * Load credentials from the local session, throwing an exception if
             * they are not present.
             * 
             * @returns {Security}  this instance
             */
            loadSession : function() {
                console.log("Logged in using session credentials.");
                this.username = expectString(sessionStorage.user);
                this.password = expectString(sessionStorage.pass);
                return this;
            },

            /**
             * Logout any logged in user, clearing both the session and the
             * local storage.
             */
            logout : function() {
                console.log("Logged out.");
                localStorage.user   = null;
                localStorage.pass   = null;
                sessionStorage.user = null;
                sessionStorage.pass = null;
                return this;
            },

            ////////////////////////////////////////////////////////////////////
            //              Basic Authentication in HTTP requests             //
            ////////////////////////////////////////////////////////////////////

            /**
             * Send a http 'POST' request to the specified url, using basic
             * authentication authered by the currently logged in user.
             * <p>
             * The configuration can be left out or be either a callback 
             * function or an object containing the following keys:
             * <ul>
             *     <li>config.data:      Object to be sent as JSON
             *     <li>config.onSuccess: Callback if the command succeeds
             *     <li>config.onFailure: Callback if the command fails
             * </ul>
             * 
             * The callbacks should take two parameters, the first being any
             * data sent back from the server and the second being the status
             * code of the request. The data will be decoded from its original
             * JSON format automatically.
             * 
             * @param {string} url      the url to send the request to
             * @param {object|function} config  a configuration object
             * @returns {Security}      this instance
             */
            post : function(url, config) {
                return this.send('POST', url, config);
            },
            
            /**
             * Send a http 'PUT' request to the specified url, using basic
             * authentication authered by the currently logged in user.
             * <p>
             * The configuration can be left out or be either a callback 
             * function or an object containing the following keys:
             * <ul>
             *     <li>config.data:      Object to be sent as JSON
             *     <li>config.onSuccess: Callback if the command succeeds
             *     <li>config.onFailure: Callback if the command fails
             * </ul>
             * 
             * The callbacks should take two parameters, the first being any
             * data sent back from the server and the second being the status
             * code of the request. The data will be decoded from its original
             * JSON format automatically.
             * 
             * @param {string} url      the url to send the request to
             * @param {object|function} config  a configuration object
             * @returns {Security}      this instance
             */
            put : function(url, config) {
                return this.send('PUT', url, config);
            },
            
            /**
             * Send a http 'GET' request to the specified url, using basic
             * authentication authered by the currently logged in user.
             * <p>
             * The configuration can be left out or be either a callback 
             * function or an object containing the following keys:
             * <ul>
             *     <li>config.data:      Object to be sent as JSON
             *     <li>config.onSuccess: Callback if the command succeeds
             *     <li>config.onFailure: Callback if the command fails
             * </ul>
             * 
             * The callbacks should take two parameters, the first being any
             * data sent back from the server and the second being the status
             * code of the request. The data will be decoded from its original
             * JSON format automatically.
             * 
             * @param {string} url      the url to send the request to
             * @param {object|function} config  a configuration object
             * @returns {Security}      this instance
             */
            get : function(url, config) {
                return this.send('GET', url, config);
            },
            
            /**
             * Send a http 'DELETE' request to the specified url, using basic
             * authentication authered by the currently logged in user.
             * <p>
             * The configuration can be left out or be either a callback 
             * function or an object containing the following keys:
             * <ul>
             *     <li>config.data:      Object to be sent as JSON
             *     <li>config.onSuccess: Callback if the command succeeds
             *     <li>config.onFailure: Callback if the command fails
             * </ul>
             * 
             * The callbacks should take two parameters, the first being any
             * data sent back from the server and the second being the status
             * code of the request. The data will be decoded from its original
             * JSON format automatically.
             * 
             * @param {string} url      the url to send the request to
             * @param {object|function} config  a configuration object
             * @returns {Security}      this instance
             */
            delete : function(url, config) {
                return this.send('DELETE', url, config);
            },
            
            /**
             * Send a http 'OPTIONS' request to the specified url, using basic
             * authentication authered by the currently logged in user.
             * <p>
             * The configuration can be left out or be either a callback 
             * function or an object containing the following keys:
             * <ul>
             *     <li>config.data:      Object to be sent as JSON
             *     <li>config.onSuccess: Callback if the command succeeds
             *     <li>config.onFailure: Callback if the command fails
             * </ul>
             * 
             * The callbacks should take two parameters, the first being any
             * data sent back from the server and the second being the status
             * code of the request. The data will be decoded from its original
             * JSON format automatically.
             * 
             * @param {string} url      the url to send the request to
             * @param {object|function} config  a configuration object
             * @returns {Security}      this instance
             */
            options : function(url, config) {
                return this.send('OPTIONS', url, config);
            },
            
            /**
             * Send a http request with a custom method to the specified url,
             * using basic authentication authered by the currently logged in 
             * user.
             * <p>
             * The configuration can be left out or be either a callback 
             * function or an object containing the following keys:
             * <ul>
             *     <li>config.data:      Object to be sent as JSON
             *     <li>config.onSuccess: Callback if the command succeeds
             *     <li>config.onFailure: Callback if the command fails
             * </ul>
             * 
             * The callbacks should take two parameters, the first being any
             * data sent back from the server and the second being the status
             * code of the request. The data will be decoded from its original
             * JSON format automatically.
             * 
             * @param {string} method   the HTTP request method to use
             * @param {string} url      the url to send the request to
             * @param {object|function} config  a configuration object
             * @returns {Security}      this instance
             */
            send : function(method, url, config) {
                expectString(method);
                
                var onSuccess = function() {};
                var onFailure = function() {};
                var data      = '';
                
                var xhttp = new XMLHttpRequest();
                xhttp.open(method, url, true);
                
                if (typeof(config) === 'undefined') {
                    // Do nothing.
                } else if (typeof(config) === 'function') {
                    onSuccess = config;
                    onFailure = config;
                } else if (typeof(config) === 'string') {
                    xhttp.setRequestHeader('Content-Type', 
                        'application/x-www-form-urlencoded');
                    data = encodeURI(config.data);
                } else if (typeof(config) === 'object') {
                    xhttp.setRequestHeader('Content-Type', 'application/json');
                    onSuccess = functionOr(config.onSuccess, function() {});
                    onFailure = functionOr(config.onFailure, function() {});
                    data      = JSON.stringify(config.data);
                } else {
                    throw 'Unexpected "config" type. Should be either an ' + 
                        'object or a function.';
                }
                
                xhttp.onreadystatechange = function() {
                    if (this.readyState === 4 ) {
                        var res    = JSON.parse(xhttp.responseText);
                        var status = expectNumber(xhttp.status);
                        switch (status) {
                            case 200 : case 201 : case 202 : case 203 :
                            case 204 :
                                onSuccess(res, status);
                                break;
                            default :
                                onFailure(res, status);
                                break;
                        }
                    }
                };
                
                xhttp.withCredentials = true;
                console.log('user: ' + this.username);
                console.log('pass: ' + this.password);
                
                xhttp.setRequestHeader('Authorization', 'Basic ' + 
                    btoa(this.username + ':' + this.password));
            
                if (data === '') {
                    xhttp.send();
                } else {
                    xhttp.send(data);
                }
            }
        };
    } else {
        console.warn('Library "Security" already defined.');
    }
})(window);