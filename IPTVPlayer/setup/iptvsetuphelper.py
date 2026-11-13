# -*- coding: utf-8 -*-

###################################################
# LOCAL import
###################################################
from Plugins.Extensions.IPTVPlayer.tools.iptvtools import printDBG, iptv_system
###################################################

###################################################
# FOREIGN import
###################################################
###################################################

LOG_DATA_MAX = 1000


class CCmdValidator:
    def __init__(self, finishCallback, validatorFun, cmdTabs):
        printDBG("CCmdValidator.__init__ ---------------------------------")
        self.cmdTabs = cmdTabs
        self.stsTab = []
        self.dataTab = []
        self.finishCallback = finishCallback
        self.validatorFun = validatorFun
        self.detectIdx = 0

        self.outData = ""
        # flags
        self.termination = False
        self.cmd = None

    def __del__(self):
        printDBG("CCmdValidator.__del__ ---------------------------------")

    def start(self):
        printDBG("CCmdValidator.start")
        self.outData = ""
        self.detectIdx = 0
        self._detect()

    def terminate(self):
        self.termination = True
        self.finishCallback = None
        self.validatorFun = None
        if self.cmd:
            self.cmd.kill(False)
        self.cmd = None

    def finish(self):
        printDBG('CCmdValidator.finish detectIdx[%r]' % self.detectIdx)
        if self.termination:
            return

        finishCallback = self.finishCallback
        self.finishCallback = None
        self.validatorFun = None

        self.cmdTabs = []
        self.outData = ""
        finishCallback(self.stsTab, self.dataTab)

    def _cmdFinished(self, code, data):
        # long outputs (the package list of "opkg list") only shortened into the debug log
        logData = data if len(data) <= LOG_DATA_MAX else '%s ... (%d characters)' % (data[:LOG_DATA_MAX], len(data))
        printDBG("CCmdValidator._cmdFinished cmd[%r] code[%r], data[%r]" % (self.cmdTabs[self.detectIdx], code, logData))
        if self.termination:
            return
        self.cmd = None
        sts, cont = self.validatorFun(code, data)
        self.stsTab.append(sts)
        self.dataTab.append(data)
        if cont and (self.detectIdx + 1) < len(self.cmdTabs):
            self.detectIdx += 1
            self._detect()
        else:
            self.finish()

    def _detect(self):
        self.cmd = iptv_system(self.cmdTabs[self.detectIdx], self._cmdFinished)
