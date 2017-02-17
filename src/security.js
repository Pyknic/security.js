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
        //                           Internal methods                         //
        ////////////////////////////////////////////////////////////////////////
        
        var expectString = function(s) {
            if (typeof(s) === 'string') {
                return s;
            } else {
                throw 'Specified value "' + s + '" is not a string.';
            }
        };

        var expectNumber = function(n) {
            if (typeof(n) === 'number') {
                return n;
            } else {
                throw 'Specified value "' + n + '" is not a number.';
            }
        };

        var functionOr = function(f, otherwise) {
            if (typeof(f) === 'function') {
                return f;
            } else if (typeof(f) === 'undefined') {
                return otherwise;
            } else {
                throw 'Expected function, but got "' + typeof(f) + '".';
            }
        };
        
        ////////////////////////////////////////////////////////////////////////
        //                              Constructor                           //
        ////////////////////////////////////////////////////////////////////////
        
        window.Security = {
            
            ////////////////////////////////////////////////////////////////////
            //                         Member Variables                       //
            ////////////////////////////////////////////////////////////////////
            user : null,
            pass : null,

            ////////////////////////////////////////////////////////////////////
            //                        Manage Credentials                      //
            ////////////////////////////////////////////////////////////////////

            getUsername : function() {
                return this.user;
            },

            getPassword : function() {
                return this.pass;
            },
            
            isLoggedIn : function() {
                return this.user !== null
                    && this.pass !== null;
            },
            
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

            login : function(user, pass, remember) {
                this.user = user;
                this.pass = pass;

                if (remember) {
                    localStorage.user = user;
                    localStorage.pass = pass;
                } else {
                    sessionStorage.user = user;
                    sessionStorage.pass = pass;
                }
                
                return this;
            },

            loadStored : function() {
                this.user = localStorage.user;
                this.pass = localStorage.pass;
                return this;
            },
            
            loadSession : function() {
                this.user = sessionStorage.user;
                this.pass = sessionStorage.pass;
                return this;
            },

            logout : function() {
                localStorage.user   = null;
                localStorage.pass   = null;
                sessionStorage.user = null;
                sessionStorage.pass = null;
                return this;
            },

            ////////////////////////////////////////////////////////////////////
            //              Basic Authentication in HTTP requests             //
            ////////////////////////////////////////////////////////////////////

            post : function(url, config) {
                return this.send('POST', url, config);
            },
            
            put : function(url, config) {
                return this.send('PUT', url, config);
            },
            
            get : function(url, config) {
                return this.send('GET', url, config);
            },
            
            delete : function(url, config) {
                return this.send('DELETE', url, config);
            },
            
            options : function(url, config) {
                return this.send('OPTIONS', url, config);
            },
            
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
                console.log('user: ' + this.user);
                console.log('pass: ' + this.pass);
                
                xhttp.setRequestHeader('Authorization', 'Basic ' + 
                    btoa(this.user + ':' + this.pass));
            
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