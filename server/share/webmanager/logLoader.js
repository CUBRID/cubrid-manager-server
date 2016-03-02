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
Ext.Loader.setConfig({
	enabled : true
});

Ext.cmApi = '/cm_api';

Ext.Loader.setPath('Ext.ux', 'extjs/ux');
Ext.cwm = {};
Ext.cwm.curUrl = '';
Ext.cwm.lang = '';

Ext.Trace = function(msg) {
	try {
		var isIE = navigator.appName.indexOf("Microsoft") != -1;
		if(isIE) {
			if(window.console) {
				window.console.log(msg);
			}
		} else {
			if(console) {
				console.log(msg);
			}
		}
	} catch(e) {

	}
};

function loadScript(url){
	var headTag = document.getElementsByTagName('head')[0];
	var script = document.createElement('script');
	script.setAttribute('src', url);
	headTag.appendChild(script);
}

Ext.createWaitWin = function(){
	var waitWin = Ext.Msg.show({
		msg : '<span style="background : transparent"><img width=24 height=24 src="resources/images/loading.gif" '
			+ 'style="marigin-right:10px"/></span><div align=center>&nbsp;&nbsp; '+ I18N_Util.getMsg("msgWaiting") +'</div>',
		width : 80,
		height : 40
	});
	
	return waitWin;
};

/*
 * common function for message box
 */
Ext.showSuccessWin = function(text, callback){
	var property = {
		title : I18N_Util.getMsg("titleSuccess"),
		msg : text,
		buttons : Ext.Msg.OK,
		icon : Ext.Msg.INFO
	};
	if(typeof callback === 'function'){
		property['fn'] = callback;
		property['closable'] = false;
	}
	Ext.Msg.show(property);
};

Ext.showFailureWin = function(text, callback){
	var property = {
		title : I18N_Util.getMsg("titleFailure"),
		msg : text,
		buttons : Ext.Msg.OK,
		icon : Ext.Msg.WARNING
	};
	if(typeof callback === 'function'){
		property['fn'] = callback;
		property['closable'] = false;
	}
	Ext.Msg.show(property);
};

Ext.showWarningWin = function(text, callback){
	var property = {
		title : I18N_Util.getMsg("titleWarning"),
		msg : text,
		buttons : Ext.Msg.OK,
		icon : Ext.Msg.WARNING
	};
	if(typeof callback === 'function'){
		property['fn'] = callback;
		property['closable'] = false;
	}
	Ext.Msg.show(property);
};

Ext.showErrorWin = function(text, callback){
	var property = {
		title : I18N_Util.getMsg("titleError"),
		msg : text,
		buttons : Ext.Msg.OK,
		icon : Ext.Msg.ERROR
	};
	if(typeof callback === 'function'){
		property['fn'] = callback;
		property['closable'] = false;
	}
	Ext.Msg.show(property);
};

Ext.parseUrl = function(url){
	if(typeof url !== 'string' || url === ''){
		Ext.Trace('Err: invalid URL');
	}
	
	var result = {
		protecol: '',
		host: '',
		port: '',
		params: new Object(),
		fragment: ''
	};
	var queryStartPos = url.indexOf('?');
	var fragStartPos = url.indexOf('#');
	fragStartPos = fragStartPos > 0 ? fragStartPos : url.length;
	var remainStr = url.substring(queryStartPos+1, fragStartPos);
	result['params'] = Ext.Object.fromQueryString(remainStr);
	return result;
};

Ext.cwm.curUrl = Ext.parseUrl(document.URL);
Ext.cwm.lang = Ext.cwm.curUrl['params']['lang'];
Ext.cwm.lang = typeof Ext.cwm.lang === 'string' ? Ext.cwm.lang : '';

var I18N_Util = Ext.create('cwm.common.i18n', {
	lang : Ext.cwm.lang === 'en' ? '' : Ext.cwm.lang,
	path : 'i18n',
	bundle: 'Messages'
});

I18N_Util.onReady(function(){
	loadScript("log-all.js");
});