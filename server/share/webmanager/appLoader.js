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
Ext.tip.QuickTipManager.init();
Ext.Loader.setPath('Ext.ux', 'extjs/ux');
Ext.require(['Ext.ux.CheckColumn']);

Ext.cwm = {};
Ext.cwm.prodVersion = '9.2.0.0002';
var checkUpdateJSUrl = 'http://ftp.cubrid.org/CUBRID_Tools/CUBRID_Web_Manager/checkCWMUpgrade.js';
if(Ext.cwm.prodVersion.indexOf('9.0') === 0){
	checkUpdateJSUrl = 'http://ftp.cubrid.org/CUBRID_Tools/CUBRID_Web_Manager/checkCWMUpgrade_v9.0.js';
} else if (Ext.cwm.prodVersion.indexOf('9.1') === 0){
	checkUpdateJSUrl = 'http://ftp.cubrid.org/CUBRID_Tools/CUBRID_Web_Manager/checkCWMUpgrade_v9.1.js';
} else if (Ext.cwm.prodVersion.indexOf('9.2') === 0){
	checkUpdateJSUrl = 'http://ftp.cubrid.org/CUBRID_Tools/CUBRID_Web_Manager/checkCWMUpgrade_v9.2.js';
}
Ext.cwm.exportPath = '/share/webmanager/files/';
Ext.ImagePath = 'resources/images/';
Ext.cmToken = '';
Ext.cmApi = '/cm_api';
Ext.cciApi = '/cci';
Ext.Ajax.timeout = 120000;
Ext.cwm.dbLoginTimeout = 10000;
Ext.cmStatus = 0;
Ext.currentDb = '';
Ext.cwm.curDbUser = '';
Ext.cwm.curDbUserIsDba = false;
// retry times for connect or get data from cubrid manager api
Ext.cmRetryTimes = 5;
Ext.dbmtUserName = '';
Ext.dbmtUserPwd = '';

Ext.cwm.langList = new Array();

var I18N_Lang = Ext.create('cwm.common.i18n', {
	lang : '',
	path : 'i18n',
	bundle: 'Languages'
});

Ext.cwm.lang = Ext.util.Cookies.get('lang');
Ext.cwm.lang = typeof Ext.cwm.lang === 'string' ? Ext.cwm.lang : '';

Ext.brokerIp = 'localhost';//server localhost
Ext.brokerPort = 33000;//default
Ext.dblist = new Array();

Ext.cwm.sqlLimitCount = 100;
Ext.cwm.queryDefaultPageSize = 20;
Ext.cwm.queryMaxPageSize = 50;
Ext.cwm.AutoRefreshBrokerInterval = 0;
Ext.cwm.AutoRefreshBrokerState = false;
//Named according to interface, oldBrokersInfo represents old group info, 
//oldBrokerStatus represents detail status.
Ext.cwm.oldBrokersInfo = null;
Ext.cwm.oldBrokerStatus = null;
//Monitor old data
Ext.cwm.oldDbProcStat = null;
Ext.cwm.oldHostStat = null;
Ext.cwm.oldBrokerDiagData = null;
Ext.cwm.oldDbStatDump = null;
Ext.cwm.monitorDirtyCombNewValue = '';
Ext.cwm.monitorDirtyColumn = null;
Ext.cwm.cpuTotal = 0;
Ext.cwm.memTotal = 0;
Ext.cwm.monitorTaskTimeout = 10 * 1000;
Ext.cwm.monitorTaskReq = {
	isLastSuc : true
};
// the color set of Ext.chart.theme.Monitor
Ext.cwm.monitorAreaColorSet = ['#B85916', '#B0BB73'];
Ext.cwm.chartTimeLength = 300; //300 sec.
Ext.cwm.monitorInterval = 1; //1 sec.

Ext.cwm.ColumnTypes = [['BIGINT', 'BIGINT'], ['BIT', 'BIT'], ['BIT VARYING', 'BIT VARYING'], ['BLOB', 'BLOB'], ['CLOB', 'CLOB'], ['CHAR', 'CHAR'], ['DATE', 'DATE'], ['DATETIME', 'DATETIME'], ['FLOAT', 'FLOAT'], ['DOUBLE', 'DOUBLE'], ['INTEGER', 'INTEGER'], ['MONETARY', 'MONETARY'], ['NCHAR', 'NCHAR'], ['NCHAR VARYING', 'NCHAR VARYING'], ['MULTISET', 'MULTISET'], ['NUMERIC', 'NUMERIC'], ['SEQUENCE', 'SEQUENCE'], ['SET', 'SET'], ['SMALLINT', 'SMALLINT'], ['STRING', 'STRING'], ['TIME', 'TIME'], ['TIMESTAMP', 'TIMESTAMP'], ['VARCHAR', 'VARCHAR']];
Ext.cwm.ColumnSetSubTypes = [['BIGINT', 'BIGINT'], ['BIT', 'BIT(1)'], ['BIT VARYING', 'BIT VARYING(4096)'], ['BLOB', 'BLOB'], ['CLOB', 'CLOB'], ['CHAR', 'CHAR(1)'], ['DATE', 'DATE'], ['DATETIME', 'DATETIME'], ['FLOAT', 'FLOAT'], ['DOUBLE', 'DOUBLE'], ['INTEGER', 'INTEGER'], ['MONETARY', 'MONETARY'], ['NCHAR', 'NCHAR(1)'], ['NCHAR VARYING', 'NCHAR VARYING(4096)'], ['NUMERIC', 'NUMERIC(15,0)'], ['SMALLINT', 'SMALLINT'], ['STRING', 'STRING'], ['TIME', 'TIME'], ['TIMESTAMP', 'TIMESTAMP'], ['VARCHAR', 'VARCHAR(4096)']];

Ext.cwm.defaultFavorites = [{name : "CUBRID Home", url : "http://www.cubrid.org/"},
                            {name : "CUBRID Manual", url : "http://www.cubrid.org/manual/"},
                            {name : "CWM Wiki", url : "http://www.cubrid.org/wiki_tools/entry/cubrid-web-manager"}];
Ext.cwm.favorites = null;

Ext.cwm.autoStartupDbs = new Array();
Ext.cwm.autoStartupBrokers = new Array();

Ext.chart.theme.Monitor = Ext.extend(Ext.chart.theme.Base, {
    constructor: function(config) {
        Ext.chart.theme.Base.prototype.constructor.call(this, Ext.apply({
            colors: ['#B85916', '#B0BB73']
        }, config));
    }
});

Ext.chart.series.Gauge.override({
	isItemInPoint: function(x, y, item, i) {
		var chartBBox = this.chart.chartBBox;
		var centerX = this.centerX = chartBBox.x + (chartBBox.width / 2);
		var centerY = this.centerY = chartBBox.y + chartBBox.height;
		var outerRadius = Math.min(centerX - chartBBox.x, centerY - chartBBox.y);
		var innerRadius = outerRadius * +this.donut / 100;
		var r = Math.sqrt(Math.pow(centerX-x, 2) + Math.pow(centerY-y,2));
		return r > innerRadius && r < outerRadius;
	}
});

function loadScript(url){
	var headTag = document.getElementsByTagName('head')[0];
	var script = document.createElement('script');
	script.setAttribute('src', url);
	headTag.appendChild(script);
}

var I18N_Util = Ext.create('cwm.common.i18n', {
	lang : Ext.cwm.lang === 'en' ? '' : Ext.cwm.lang,
	path : 'i18n',
	bundle: 'Messages'
});

I18N_Lang.onReady(function(){
	Ext.cwm.langList = [
    	{key: 'en', value: I18N_Lang.getMsg("langEn")},
    	{key: 'ko', value: I18N_Lang.getMsg("langKo")}
	];
	/*TOOLS-3736 Make sure that initial Ext.cwm.langList before load cwm-all.js*/
	I18N_Util.onReady(function(){
		loadScript("cwm-all.js");
	});
});
