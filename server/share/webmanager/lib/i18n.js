/*
 * Copyright (C) 2008-2015 Search Solution Corporation. All rights reserved by Search Solution.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 3 of the License, or 
 *   (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
Ext.define('cwm.common.i18n', {
	defaultBundle: 'Messages',
	defaultExt: '.properties',
	defaultPath: 'i18n',
	
	constructor: function(config){
		config = config || {};
		var me = this;
		me.bundle = config.bundle || me.defaultBundle;
		me.language = config.lang || null;//me.guessLanguage();
		me.ext = config.ext || me.defaultExt;
		me.path = config.path || me.defaultPath;		
		me.url = me.buildURL(me.language);
	},
	
	getMsg: function(msgKey, macroReplace){
		var me = this;
		var value = me.msgMap ? me.msgMap.get(msgKey) : null;
		if( value == null ) {
			value = "{" + me.bundle + "."+ msgKey + "}";
			return value;
		}
		if( macroReplace != null && Ext.isObject(macroReplace) ) {
			for( var name in macroReplace ){
				value = value.replace( new RegExp("{" + name + "}","gi"), macroReplace[name] );
			}
		}
		return value;
	},

	onReady: function(callbackFunc){
		var me = this;
		me.loadMessages(callbackFunc);
	},

	guessLanguage: function(){
		return (navigator.language || navigator.browserLanguage
				|| navigator.userLanguage || this.defaultLanguage);
	},

	buildURL: function(language){
		var url = '';
		if (this.path) url+= this.path + '/';
		url+=this.bundle;
		if (language) url+= '_'+language;
		url+=this.ext;
		return url;
	},

	loadDefaultMessages: function(callbackFunc){
		var me = this;
		Ext.Ajax.request({
			disableCaching: false,
			url: me.buildURL(),
			callback: function(opt, success, response){
				if( success ) {
					me.parseResponseData(response, callbackFunc);
					return;
				}
				if(Ext.isFunction(callbackFunc)) {
					callbackFunc();
				}
			}
		});
	},

	loadMessages: function(callbackFunc){
		var me = this;
		if(me.language) {
			Ext.Ajax.request({
				disableCaching: false,
				url: me.buildURL(me.language),
				callback: function(opt, success, response){
					if( success ) {
						me.parseResponseData(response, callbackFunc);
						return;
					}
					me.loadDefaultMessages(callbackFunc);
				}
			});
		} else {
			me.loadDefaultMessages(callbackFunc);
		}
	},

	parseResponseData: function(response, callbackFunc){
		var me = this;
		var mapData = me.getData(response);
		if(Ext.isFunction(callbackFunc)) {
			callbackFunc();
		}
	},
	
	getData: function(data){
		var me = this;
		me.msgMap = new Ext.util.HashMap();
        var record,
			f = this.readLines(data),
			l = f.length;
		for(var i = 0; i < l; i++){
			var kl = f[i].search(/[\s:=]/);
			record = {
				key : this.clearKeyExtraChars(f[i].substring(0, kl)),
				value : this.clearValueExtraChars(f[i].substring(kl+1))
			};
			me.msgMap.add(record.key, record.value);
		}
		return me.msgMap;
	},

	clearKeyExtraChars: function(s){
		return (s ? s.replace(/[:=]/gi, "") : "");
	},
	
	clearValueExtraChars: function(s){
		return (s ? s.replace(/\r*\n*$/gi, "") : "");
	},
	
	readLines: function(data){
		var file = data.responseText;
		return (file ? file.match(/.*(.*\\\s*\n)+.*|^((?!^\s*[#!]).).*$/gim) : []);
	}
});