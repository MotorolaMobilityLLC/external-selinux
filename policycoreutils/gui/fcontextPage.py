## fcontextPage.py - show selinux mappings
## Copyright (C) 2006 Red Hat, Inc.

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.

## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

## Author: Dan Walsh
import gtk
import gtk.glade
import os
import gobject
import seobject
import commands
from semanagePage import *

SPEC_COL = 0
TYPE_COL = 1
FTYPE_COL = 2


class context:

    def __init__(self, scontext):
        self.scontext = scontext
        con = scontext.split(":")
        self.type = con[0]
        if len(con) > 1:
            self.mls = con[1]
        else:
            self.mls = "s0"

    def __str__(self):
        return self.scontext

##
## I18N
##
PROGNAME = "policycoreutils"
try:
    import gettext
    kwargs = {}
    if sys.version_info < (3,):
        kwargs['unicode'] = True
    gettext.install(PROGNAME,
                    localedir="/usr/share/locale",
                    codeset='utf-8',
                    **kwargs)
except:
    try:
        import builtins
        builtins.__dict__['_'] = str
    except ImportError:
        import __builtin__
        __builtin__.__dict__['_'] = unicode


class fcontextPage(semanagePage):

    def __init__(self, xml):
        semanagePage.__init__(self, xml, "fcontext", _("File Labeling"))
        self.fcontextFilter = xml.get_widget("fcontextFilterEntry")
        self.fcontextFilter.connect("focus_out_event", self.filter_changed)
        self.fcontextFilter.connect("activate", self.filter_changed)

        self.store = gtk.ListStore(gobject.TYPE_STRING, gobject.TYPE_STRING, gobject.TYPE_STRING)
        self.view = xml.get_widget("fcontextView")
        self.view.set_model(self.store)
        self.view.set_search_equal_func(self.search)

        col = gtk.TreeViewColumn(_("File\nSpecification"), gtk.CellRendererText(), text=SPEC_COL)
        col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        col.set_fixed_width(250)

        col.set_sort_column_id(SPEC_COL)
        col.set_resizable(True)
        self.view.append_column(col)
        col = gtk.TreeViewColumn(_("Selinux\nFile Type"), gtk.CellRendererText(), text=TYPE_COL)

        col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        col.set_fixed_width(250)
        col.set_sort_column_id(TYPE_COL)
        col.set_resizable(True)
        self.view.append_column(col)
        col = gtk.TreeViewColumn(_("File\nType"), gtk.CellRendererText(), text=2)
        col.set_sort_column_id(FTYPE_COL)
        col.set_resizable(True)
        self.view.append_column(col)

        self.store.set_sort_column_id(SPEC_COL, gtk.SORT_ASCENDING)
        self.load()
        self.fcontextEntry = xml.get_widget("fcontextEntry")
        self.fcontextFileTypeCombo = xml.get_widget("fcontextFileTypeCombo")
        liststore = self.fcontextFileTypeCombo.get_model()
        for k in seobject.file_types:
            if len(k) > 0 and k[0] != '-':
                iter = liststore.append()
                liststore.set_value(iter, 0, k)
        iter = liststore.get_iter_first()
        self.fcontextFileTypeCombo.set_active_iter(iter)
        self.fcontextTypeEntry = xml.get_widget("fcontextTypeEntry")
        self.fcontextMLSEntry = xml.get_widget("fcontextMLSEntry")

    def match(self, fcon_dict, k, filter):
        try:
            f = filter.lower()
            for con in k:
                k = con.lower()
                if k.find(f) >= 0:
                    return True
            for con in fcon_dict[k]:
                k = con.lower()
                if k.find(f) >= 0:
                    return True
        except:
            pass
        return False

    def load(self, filter=""):
        self.filter = filter
        self.fcontext = seobject.fcontextRecords()
        self.store.clear()
        fcon_dict = self.fcontext.get_all(self.local)
        keys = fcon_dict.keys()
        keys.sort()
        for k in keys:
            if not self.match(fcon_dict, k, filter):
                continue
            iter = self.store.append()
            self.store.set_value(iter, SPEC_COL, k[0])
            self.store.set_value(iter, FTYPE_COL, k[1])
            if fcon_dict[k]:
                rec = "%s:%s" % (fcon_dict[k][2], seobject.translate(fcon_dict[k][3], False))
            else:
                rec = "<<None>>"
            self.store.set_value(iter, TYPE_COL, rec)
        self.view.get_selection().select_path((0,))

    def filter_changed(self, *arg):
        filter = arg[0].get_text()
        if filter != self.filter:
            self.load(filter)

    def dialogInit(self):
        store, iter = self.view.get_selection().get_selected()
        self.fcontextEntry.set_text(store.get_value(iter, SPEC_COL))
        self.fcontextEntry.set_sensitive(False)
        scontext = store.get_value(iter, TYPE_COL)
        scon = context(scontext)
        self.fcontextTypeEntry.set_text(scon.type)
        self.fcontextMLSEntry.set_text(scon.mls)
        type = store.get_value(iter, FTYPE_COL)
        liststore = self.fcontextFileTypeCombo.get_model()
        iter = liststore.get_iter_first()
        while iter != None and liststore.get_value(iter, 0) != type:
            iter = liststore.iter_next(iter)
        if iter != None:
            self.fcontextFileTypeCombo.set_active_iter(iter)
        self.fcontextFileTypeCombo.set_sensitive(False)

    def dialogClear(self):
        self.fcontextEntry.set_text("")
        self.fcontextEntry.set_sensitive(True)
        self.fcontextFileTypeCombo.set_sensitive(True)
        self.fcontextTypeEntry.set_text("")
        self.fcontextMLSEntry.set_text("s0")

    def delete(self):
        store, iter = self.view.get_selection().get_selected()
        try:
            fspec = store.get_value(iter, SPEC_COL)
            ftype = store.get_value(iter, FTYPE_COL)
            self.wait()
            (rc, out) = commands.getstatusoutput("semanage fcontext -d -f '%s' '%s'" % (ftype, fspec))
            self.ready()

            if rc != 0:
                return self.error(out)
            store.remove(iter)
            self.view.get_selection().select_path((0,))
        except ValueError, e:
            self.error(e.args[0])

    def add(self):
        ftype = ["", "--", "-d", "-c", "-b", "-s", "-l", "-p"]
        fspec = self.fcontextEntry.get_text().strip()
        type = self.fcontextTypeEntry.get_text().strip()
        mls = self.fcontextMLSEntry.get_text().strip()
        list_model = self.fcontextFileTypeCombo.get_model()
        active = self.fcontextFileTypeCombo.get_active()
        self.wait()
        (rc, out) = commands.getstatusoutput("semanage fcontext -a -t %s -r %s -f '%s' '%s'" % (type, mls, ftype[active], fspec))
        self.ready()
        if rc != 0:
            self.error(out)
            return False

        iter = self.store.append()
        self.store.set_value(iter, SPEC_COL, fspec)
        self.store.set_value(iter, FTYPE_COL, ftype)
        self.store.set_value(iter, TYPE_COL, "%s:%s" % (type, mls))

    def modify(self):
        fspec = self.fcontextEntry.get_text().strip()
        type = self.fcontextTypeEntry.get_text().strip()
        mls = self.fcontextMLSEntry.get_text().strip()
        list_model = self.fcontextFileTypeCombo.get_model()
        iter = self.fcontextFileTypeCombo.get_active_iter()
        ftype = list_model.get_value(iter, 0)
        self.wait()
        (rc, out) = commands.getstatusoutput("semanage fcontext -m -t %s -r %s -f '%s' '%s'" % (type, mls, ftype, fspec))
        self.ready()
        if rc != 0:
            self.error(out)
            return False

        store, iter = self.view.get_selection().get_selected()
        self.store.set_value(iter, SPEC_COL, fspec)
        self.store.set_value(iter, FTYPE_COL, ftype)
        self.store.set_value(iter, TYPE_COL, "%s:%s" % (type, mls))
