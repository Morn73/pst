#!/usr/bin/python
# pst 0.1 -- password storage
# Copyright (C) Tobias Kaiser <mail@tb-kaiser.de> 2013

import os
import json
import base64
import string

import pygtk
pygtk.require('2.0')
import gtk
import pango

from Crypto.Cipher import CAST
from Crypto.Hash import SHA256
from Crypto.Random._UserFriendlyRNG import get_random_bytes

class Storage:
    keyfile_identity="pstpstpst"

    def cipher(self, key):
        return CAST.new(key,
            IV="\0\0\0\0\0\0\0\0",
            mode=CAST.MODE_CBC)
        

    def generate_master_key(self):
        self.key=get_random_bytes(16)

    def file_of_rid(self, rid):
        return os.path.join(self.path, "pstobj%s"%rid)

    def rid_of_file(self, filename):
        return filename[len(filename)-16:]

    def new_rid(self):
        while True:
            rid=base64.b16encode(get_random_bytes(8))
            if not os.path.exists(self.file_of_rid(rid)): return rid

    def add_record(self, record):
        rid=self.new_rid()
        f=open(self.file_of_rid(rid), "w")
        f.write(self.encrypt(json.dumps(record)))
        f.close()
        return rid

    def update_record(self, rid, record):
        f=open(self.file_of_rid(rid), "w")
        f.write(self.encrypt(json.dumps(record)))
        f.close()

    def remove_record(self, rid):
        os.unlink(self.file_of_rid(rid))

    def records(self):
        files=filter(lambda x: x.startswith("pstobj"),
            os.listdir(self.path))
        records={}
        for filename in files:
            f=open(os.path.join(self.path, filename), "r")
            records[self.rid_of_file(filename)]=\
                json.loads(self.decrypt(f.read()))
            f.close()
        return records

    def save_master_key(self, passphrase):
        passphrase_hash=SHA256.new(passphrase).digest()[:16]
        key_encrypted=self.cipher(passphrase_hash).encrypt(self.key)
        if not os.path.exists(self.path):
            os.mkdir(self.path)
        f=open(self.master_key_file, "w")
        f.write(key_encrypted+self.encrypt(self.keyfile_identity, pad_to=8))
        f.close()

    def encrypt(self, text, pad_to=8):
        text=get_random_bytes(16)+text
        n_padding_bits=(pad_to-len(text)%pad_to)%pad_to
        text+="\0"*n_padding_bits
        return self.cipher(self.key).encrypt(text)
        
    def decrypt(self, text, key=None):
        if not key: key=self.key
        return self.cipher(key).decrypt(text)[16:].strip("\0")

    def load_master_key(self, passphrase):
        passphrase_hash=SHA256.new(passphrase).digest()[:16]
        f=open(self.master_key_file, "r")
        key_encrypted=f.read(16)
        check=f.read()
        f.close()
        possible_key=self.cipher(passphrase_hash).decrypt(key_encrypted) 
        if self.decrypt(check, possible_key) == self.keyfile_identity:
            self.key=possible_key
            return True
        else:
            return False


    def __init__(self, path):
        self.path=path
        self.master_key_file=os.path.join(path, "master.key") 
    
    def first_usage(self):
        return not os.path.exists(self.master_key_file)

    def broken(self):
        return (not os.path.exists(self.master_key_file)) \
            and os.path.exists(self.path) \
            and len(os.listdir(self.path))>0

class PasswordTrainerWindow:
    def update_label(self):
        masked_pw='?'*self.learned_chars+self.password[self.learned_chars:]
        self.pw_label.set_text(masked_pw)
        
    def __init__(self, password):
        self.password=password
        self.learned_chars=0

        self.window=gtk.Window()
        self.window.set_border_width(3)
        vbox=gtk.VBox()

        self.pw_label=gtk.Label()
        self.pw_label.show()
        self.pw_label.modify_font(pango.FontDescription('monospace'))
        
        manual_label=gtk.Label("This is the password trainer."+
            "\nYou learn new passwords by entering them many times."+
            "\nEach time you type your password correctly,\n one character "
            "of your password disappears.\n"
            "This helps you to remember your password.")
        manual_label.show()

        self.info_label=gtk.Label()
        self.info_label.show()
        

        self.pw_entry=gtk.Entry()
        self.pw_entry.set_visibility(False)
        self.pw_entry.show()
        self.pw_entry.set_activates_default(True)

        enter=gtk.Button("Enter")
        enter.set_flags(gtk.CAN_DEFAULT)
        enter.connect("clicked", lambda x, y: self.enter(), None)
        enter.show()


        vbox.pack_start(manual_label, padding=5)
        vbox.pack_start(self.pw_label)
        vbox.pack_start(self.info_label, padding=10)
        vbox.pack_start(self.pw_entry, False, False, padding=2)
        vbox.pack_start(enter, False, False, padding=2)

        vbox.show()

        self.window.add(vbox)
        self.window.set_default_size(300, 150)
        self.window.set_default(enter)
        self.window.set_title("Password Trainer")
        self.window.show()

        self.update_label()

    def enter(self):
        if self.pw_entry.get_text()==self.password:
            self.info_label.set_markup("<b><span color='darkgreen'>Right password.</span></b>")
            self.learned_chars+=1
            if self.learned_chars>len(self.password):
                self.learned_chars=len(self.password)
        else:
            self.info_label.set_markup("<b><span color='red'>Wrong password.</span></b>")
            self.learned_chars-=1
            if self.learned_chars<0: self.learned_chars=0

        self.pw_entry.set_text("")


        self.update_label()

class RecordWindow:
    def build_record(self):
        path=self.path_entry.get_text()
        return (path, self.rec_type, self.data_elem())  

    def save(self):
        
        record=self.build_record()
        self.storage.update_record(self.rid, record)
        self.populate(record)

        self.main.update_tree()
        self.main.expand_down_to(record[0])

    def close(self):
        if not self.delete_event(None, None):
            self.window.destroy()

    def remove(self):
        self.storage.remove_record(self.rid)
        self.main.update_tree()
        self.window.destroy()

    def destroy(self, widget, data=None):
        self.main.open_records.remove(self)
    
    def delete_event(self, widget, event, data=None):
        if json.dumps(self.build_record())\
            ==json.dumps(self.storage.records()[self.rid]):
            return False

        # False -> destroy, True -> dont destroy
        m=gtk.MessageDialog(type=gtk.MESSAGE_QUESTION,
            message_format="There are unsaved changed to record \"%s\"."
            % self.path_entry.get_text() +
            " Do you want to save the record?"
            )
        m.set_title("Unsaved Changes")
        m.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        m.add_button(gtk.STOCK_YES, gtk.RESPONSE_YES)
        m.add_button(gtk.STOCK_NO, gtk.RESPONSE_NO)
        result=m.run()
        m.destroy()
        if result==gtk.RESPONSE_CANCEL:
            return True
        else:
            if result==gtk.RESPONSE_YES:
                self.save() 
            return False

    def __init__(self, rid, storage, main):
        self.rid=rid
        self.storage=storage
        self.main=main
        
        record=self.storage.records()[rid]

        self.window=gtk.Window()
        self.window.set_border_width(3)
        self.window.connect("destroy", self.destroy)
        self.window.connect("delete_event", self.delete_event)
        vbox=gtk.VBox()

        hbox=gtk.HBox()
        l=gtk.Label("Path:")
        l.show()
        hbox.pack_start(l, False, False, 5)

        self.path_entry=gtk.Entry()
        self.path_entry.show()
        hbox.pack_start(self.path_entry)

        vbox.pack_start(hbox, False, False, 5)
        hbox.show()

        self.record_vbox=gtk.VBox()
        self.record_vbox.show()
        vbox.pack_start(self.record_vbox)

        hbox=gtk.HBox()

        b=gtk.Button(stock=gtk.STOCK_SAVE)
        hbox.pack_start(b, padding=5)
        b.connect("clicked", lambda x, y: self.save(), None)
        b.show()

        b=gtk.Button(stock=gtk.STOCK_DELETE)
        hbox.pack_start(b, padding=5)
        b.connect("clicked", lambda x, y: self.remove(), None)
        b.show()

        b=gtk.Button(stock=gtk.STOCK_CLOSE)
        hbox.pack_start(b, padding=5)
        b.connect("clicked", lambda x, y: self.close(), None)
        b.show()
        vbox.pack_start(hbox, False, False, 5)
        hbox.show()

        vbox.show()

        self.window.add(vbox)
        
        self.window.show()

    def populate(self, record):
        self.window.set_title(record[0])
        self.path_entry.set_text(record[0])


class TextRecordWindow(RecordWindow):
    rec_type="text"
    rec_desc="text record"
    init_with=""
    def __init__(self, rid, storage, main):
        RecordWindow.__init__(self, rid, storage, main)

        l=gtk.Label("Text:")
        l.show()
        self.record_vbox.pack_start(l)
        
        self.text_view=gtk.TextView()
        self.text_view.show()
        scrolled_win=gtk.ScrolledWindow()
        scrolled_win.add_with_viewport(self.text_view)
        scrolled_win.show()
        scrolled_win.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scrolled_win.set_size_request(250, 100)
        self.record_vbox.pack_start(scrolled_win)

        self.populate(self.storage.records()[self.rid])  

    def populate(self, record):
        RecordWindow.populate(self,record)
        self.text_view.get_buffer().set_text(record[2])
        
    def data_elem(self):
        buf=self.text_view.get_buffer()
        text=buf.get_text(buf.get_start_iter(), buf.get_end_iter())
        return text

class PasswordRecordWindow(RecordWindow):
    rec_type="password"
    rec_desc="password record"
    init_with={
        "username":"",
        "password":"",
        "mail":"",
        "url":"",
        "notes":""
        }
    
    default_pw_size=15
    pw_ingredients=(
        ("Lowercase letters", True, string.lowercase), 
        ("Uppercase letters", True, string.uppercase), 
        ("Digits", True, string.digits), 
        ("Punctuation", False, string.punctuation)
    )

    def pw_train(self, a, b):
        PasswordTrainerWindow(self.entry["password"].get_text())
        self.pw_show_button.set_active(False)

    def pw_gen_dialog(self, a, b):
        dialog = gtk.Dialog("Generate Password")
        dialog.set_border_width(3)
        dialog.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        dialog.add_button(gtk.STOCK_OK, gtk.RESPONSE_OK)
        dialog.set_default_response(gtk.RESPONSE_OK)

        h=gtk.HBox()
        l=gtk.Label("Character count:")
        l.show()
        h.pack_start(l, False, False, padding=5)
        character_count_entry=gtk.Entry()
        character_count_entry.set_text(str(self.default_pw_size))
        character_count_entry.show()
        h.pack_start(character_count_entry)
        h.show()
        dialog.get_content_area().pack_start(h, padding=5)

        ing_opts=[]
        for label_text, default, content in self.pw_ingredients:
            cb=gtk.CheckButton(label_text)
            cb.set_active(default)
            cb.show()
            dialog.get_content_area().pack_start(cb, padding=5)
            ing_opts.append(cb)

        if dialog.run()==gtk.RESPONSE_OK:
            size=int(character_count_entry.get_text())
            select_from=[]
            for i in range(len(self.pw_ingredients)):
                if ing_opts[i].get_active():
                    select_from+=self.pw_ingredients[i][2]
            self.generate(select_from, size)  
        dialog.destroy()
        
    def generate(self, select_from, count):
        if len(select_from)<1: return
        result=""
        for i in range(count):
            while True:
                c=get_random_bytes(1)
                if c in select_from: break
            result+=c 
        self.entry["password"].set_text(result)

    def update_pw_gen_clickable(self):
        pw_set=len(self.entry["password"].get_text())!=0
        self.pw_gen_button.set_sensitive(not pw_set)
        self.pw_train_button.set_sensitive(pw_set and
            self.pw_show_button.get_active())

    def pw_show_button_toggled(self, a, b):
        self.entry["password"].set_visibility(
            self.pw_show_button.get_active()),
        self.update_pw_gen_clickable()

    def __init__(self, rid, storage, main):
        RecordWindow.__init__(self, rid, storage, main)
       
        self.entry={}
        for label, key in (
            ("Username:", "username"),
            ("Password:", "password"),
            ("Mail address:", "mail"),
            ("URL:", "url")):
            l=gtk.Label(label)
            l.show()
            self.record_vbox.pack_start(l)

            hbox=gtk.HBox()

            self.entry[key]=gtk.Entry()
            self.entry[key].show()
            hbox.pack_start(self.entry[key])

            #if key in ("username", "password"):
            #    e=gtk.Button("Copy to clipboard")
            #    e.show()
            #    hbox.pack_start(e, False, False)

            hbox.show()
            self.record_vbox.pack_start(hbox)
            
            if key=="password":
                self.entry[key].connect("changed", lambda a:
                    self.update_pw_gen_clickable());

                self.pw_show_button=gtk.ToggleButton("Show password")
                self.pw_show_button.show()
                self.pw_show_button.connect("toggled",
                    self.pw_show_button_toggled, None)
                self.record_vbox.pack_start(self.pw_show_button, padding=3)

                self.pw_gen_button=gtk.Button("Generate password")
                self.pw_gen_button.show()
                self.pw_gen_button.connect("clicked", self.pw_gen_dialog, None)
                self.record_vbox.pack_start(self.pw_gen_button, padding=3)

                self.pw_train_button=gtk.Button("Password Trainer")
                self.pw_train_button.show()
                self.pw_train_button.connect("clicked", self.pw_train, None)
                self.record_vbox.pack_start(self.pw_train_button, padding=3)

        l=gtk.Label("Notes:")
        l.show()
        self.record_vbox.pack_start(l)

        self.text_view=gtk.TextView()
        self.text_view.show()
        scrolled_win=gtk.ScrolledWindow()
        scrolled_win.add_with_viewport(self.text_view)
        scrolled_win.show()
        scrolled_win.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        scrolled_win.set_size_request(150, 100)
        self.record_vbox.pack_start(scrolled_win)

        self.populate(self.storage.records()[self.rid])  

    def populate(self, record):
        RecordWindow.populate(self,record)
        data=record[2]
        self.text_view.get_buffer().set_text(data["notes"])
        for key in ("username", "password", "mail", "url"):
            self.entry[key].set_text(data[key])

        if data["password"]=="":
            self.pw_show_button.set_active(True)
            self.entry["password"].set_visibility(True)
        else:
            self.pw_show_button.set_active(False)
            self.entry["password"].set_visibility(False)
        
    def data_elem(self):
        data={}
        buf=self.text_view.get_buffer()
        data["notes"]=buf.get_text(buf.get_start_iter(), buf.get_end_iter())
        for key in ("username", "password", "mail", "url"):
            data[key]=self.entry[key].get_text()
        return data

class GtkStorageFrontend:
    path_sep="/" 
    def set_passphrase(self, initial=False):
        dialog = gtk.Dialog("Set Passphrase")
        dialog.set_border_width(3)
        dialog.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        dialog.add_button(gtk.STOCK_OK, gtk.RESPONSE_OK)
        dialog.set_default_response(gtk.RESPONSE_OK)

        if initial:
            l=gtk.Label("No password store was found in ~/.pst."
                " Create a new password store:")
            l.show()
            dialog.get_content_area().pack_start(l, padding=5)

        l=gtk.Label("Enter your new passphrase twice:")
        l.show()
        dialog.get_content_area().pack_start(l, padding=5)

        en=[]
        for i in range(2):
            e=gtk.Entry()
            e.set_visibility(False)
            e.set_activates_default(True) 
            e.show()
            dialog.get_content_area().pack_start(e, padding=5)
            en.append(e)

        while True:
            resp=dialog.run()
            p1, p2=en[0].get_text(), en[1].get_text()
            if resp==gtk.RESPONSE_OK:
                if p1==p2:
                    dialog.destroy()
                    return True, p1
                else:
                    self.error_message("Passphrases did not match.")
                    en[0].set_text("")
                    en[1].set_text("")
            else:
                dialog.destroy()
                return False, ""

    def error_message(self, message):
        m=gtk.MessageDialog(type=gtk.MESSAGE_ERROR, message_format=message)
        m.set_border_width(3)
        m.set_title("Error")
        m.add_button(gtk.STOCK_OK, gtk.RESPONSE_OK)
        m.run()
        m.destroy()


    def ask_passphrase(self):
        dialog = gtk.Dialog("Enter Passphrase")
        dialog.set_border_width(3)
        dialog.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        dialog.add_button(gtk.STOCK_OK, gtk.RESPONSE_OK)
        dialog.set_default_response(gtk.RESPONSE_OK)

        l=gtk.Label("Enter passphrase to open password store:")
        l.show()
        dialog.get_content_area().pack_start(l, padding=5)

        e=gtk.Entry()
        e.set_visibility(False)
        e.set_activates_default(True) 
        e.show()
        dialog.get_content_area().pack_start(e, padding=5)

        while True:
            if dialog.run()==gtk.RESPONSE_OK:
                if self.storage.load_master_key(e.get_text()):
                    dialog.destroy()
                    return True
                else:
                    self.error_message("Wrong passphrase")
                    e.set_text("")
            else:
                dialog.destroy()
                return False


    def add_record(self, a, RW):
        rid=self.storage.add_record(("unnamed", RW.rec_type, RW.init_with))
        self.update_tree()
        self.open_record(rid)

    def create_missing(self, base_path, prev_nodes):
        createds={}
        for i in range(len(base_path)+1):
            cur_path=base_path[:i]
            if not (cur_path in prev_nodes):
                pred=self.treestore.append(pred,
                    [base_path[i-1], "", "",
                    reduce(lambda a, b: "%s%s%s"%(a,self.path_sep,b),
                        cur_path)])
                createds[cur_path]=pred
            else:
                pred=prev_nodes[cur_path]
        return pred, createds

    def expanded_paths(self):
        lst=[]
        self.treestore.foreach(
            lambda model, path, it, user_data: lst.append(path), None)
        expanded_paths=[]
        for row in lst:
            if self.treeview.row_expanded(row):
                it=self.treestore.get_iter(row)
                expanded_paths.append(self.treestore.get(it, 3)[0])
        sel_iter=self.treeview.get_selection().get_selected()[1]
        if sel_iter:
            selection=self.treestore.get(sel_iter, 3)[0]
        else:
            selection=None
        return (expanded_paths, selection)

    def reexpand_paths(self, inp):
        old_expandeds, selection=inp
        lst=[]
        self.treestore.foreach(
            lambda model, path, it, user_data: lst.append(path), None)
        for row in lst:
            path=self.treestore.get(self.treestore.get_iter(row), 3)[0]
            if path in old_expandeds:
                self.treeview.expand_row(row, False)
            if path==selection:
                self.treeview.get_selection().select_path(row)

    def select_upmost(self):
        # Select first non-dummy entry
        lst=[]
        self.treestore.foreach(
            lambda model, path, it, user_data: lst.append(path), None)
        for row in lst:
            type=self.treestore.get(self.treestore.get_iter(row), 1)[0]
            if type!="":
                self.treeview.get_selection().select_path(row)
                return
        

    def expand_down_to(self, path):
        lst=[]
        self.treestore.foreach(
            lambda model, path, it, user_data: lst.append(path), None)
        path=path.split(self.path_sep)
        for row in lst:
            cur_path=self.treestore.get(self.treestore.get_iter(row), 3)[0]
            cur_path=cur_path.split(self.path_sep)
            if path[:len(cur_path)]==cur_path and len(cur_path)<len(path):
                self.treeview.expand_row(row, False)

    def update_tree(self):
        filter_now=self.filter_entry.get_text()
        old_expandeds=self.expanded_paths()
        self.treestore.clear()
        l=self.storage.records().items()
        l=filter(lambda x: x[1][0].lower().find(filter_now.lower())>=0, l)
        l2=map(lambda x: (x[1][0].split(self.path_sep), x), l)
        prev_nodes={():None}
        cur_depth=1
        while len(l2)>0:
            for el in filter(lambda x: len(x[0])==cur_depth, l2):
                l2.remove(el)
                rid, rec=el[1]
                base_path=el[0]
                cur_path=tuple(el[0])
                node_name=base_path.pop() 
                base_path=tuple(base_path)
                if not base_path in prev_nodes:
                    prev_nodes[base_path], new=\
                        self.create_missing(base_path, prev_nodes)
                    prev_nodes=dict(new.items()+prev_nodes.items())
                    
                # may overwrite an existing node, dont care ;)
                prev_nodes[cur_path]=self.treestore.append(
                    prev_nodes[base_path],
                    [node_name, rid, rec[1], rec[0]])
            cur_depth+=1
        self.reexpand_paths(old_expandeds) 

    def record_clicked(self, w, path, it, data):
        rid=self.treestore.get(self.treestore.get_iter(path), 1)[0]
        self.open_record(rid)
    
    record_windows=[
        TextRecordWindow,
        PasswordRecordWindow
        ]

    def open_record(self, rid):
        for existing in self.open_records:
            if existing.rid==rid:
                existing.window.present()
                return
        
        if not rid in self.storage.records(): return  
        record_type=self.storage.records()[rid][1]

        
        for RW in self.record_windows:
            if RW.rec_type==record_type:
                self.open_records.append(RW(rid, self.storage, self))
                return
        self.error_message("Unknown record type")

    def change_passphrase(self):
        if not self.ask_passphrase(): return
        ok, passphrase=self.set_passphrase()
        if ok:
            self.storage.save_master_key(passphrase)
        else:
            self.error_message("Passphrase unchanged.")

    def destroy(self, widget, data=None):
        gtk.main_quit()
    
    def delete_event(self, widget, event, data=None):
        # False -> destroy, True -> dont destroy
        for existing in self.open_records:
            if existing.delete_event(None, None):
                return True
        return False

    def __init__(self):
        self.storage=Storage(os.path.join(os.environ["HOME"], ".pst"))
        self.filter_prev=""
        self.no_filter_exp_state=[]

        self.open_records=[]

    def filter_changed(self, a, b):
        filter_now=self.filter_entry.get_text()

        # Change from no filter -> filter
        if len(self.filter_prev)==0 and len(filter_now)>0:
            self.no_filter_exp_state=self.expanded_paths()

        self.treeview.expand_all()
        self.update_tree()
        self.select_upmost()

        # Change from filter -> no filter
        if len(filter_now)==0 and len(self.filter_prev)>0:
            self.treeview.collapse_all()
            self.reexpand_paths(self.no_filter_exp_state)

        self.filter_prev=filter_now
    
    def filter_activate(self, a, b):
        sel_iter=self.treeview.get_selection().get_selected()[1]
        if sel_iter:
            self.open_record(self.treestore.get(sel_iter, 1)[0])
        

    def run(self):
        if self.storage.broken():
            self.error_message("Failed to open password store in .pst:"
                " master.key missing")
            return
        if self.storage.first_usage():
            ok, passphrase=self.set_passphrase(initial=True)
            if not ok: return
            self.storage.generate_master_key()
            self.storage.save_master_key(passphrase)
        else:
            if not self.ask_passphrase(): return

        self.main_window=gtk.Window() 
        self.main_window.set_default_size(300,300)
        self.main_window.set_title("Password Manager")
        self.main_window.connect("destroy", self.destroy)
        self.main_window.connect("delete_event", self.delete_event)

        vbox=gtk.VBox()
        self.main_window.add(vbox)


        menu=gtk.Menu()
        menu.show()

        for RW in self.record_windows:
            g=gtk.ImageMenuItem(stock_id=gtk.STOCK_ADD)
            g.set_label("Add %s"%RW.rec_desc)
            g.connect("activate", self.add_record, RW)
            menu.append(g)
            g.show()

        g=gtk.MenuItem("Change passphrase")
        g.connect("activate", lambda x, y: self.change_passphrase(), None)
        menu.append(g)
        g.show()

        g=gtk.ImageMenuItem(stock_id=gtk.STOCK_REFRESH)
        g.connect("activate", lambda x, y: self.update_tree(), None)
        menu.append(g)
        g.show()

        g=gtk.ImageMenuItem(stock_id=gtk.STOCK_QUIT)
        g.connect("activate", lambda x, y: gtk.main_quit(), None)
        menu.append(g)
        g.show()

        root_menu = gtk.MenuItem("Store")
        root_menu.show()
        root_menu.set_submenu(menu)

        menu_bar=gtk.MenuBar()
        menu_bar.show()
        menu_bar.append(root_menu)
        vbox.pack_start(menu_bar, False, False)

        hbox=gtk.HBox()
        l=gtk.Label("Filter:")
        l.show()
        hbox.pack_start(l, False, False, padding=4)
        self.filter_entry=gtk.Entry()
        self.filter_entry.show()
        self.filter_entry.connect("changed", self.filter_changed, None)
        self.filter_entry.connect("activate", self.filter_activate, None)
        hbox.pack_start(self.filter_entry, padding=4)
        hbox.show()

        vbox.pack_start(hbox, False, False, padding=4)

        # relative path / node name, type, rid, absolute path:
        self.treestore = gtk.TreeStore(str, str, str, str)
        
        self.treeview=gtk.TreeView(self.treestore)
        self.treeview.connect("row_activated", self.record_clicked, None)

        #for data_idx, title in ((0, "Path"), (2, "Type"), (1, "RID")):
        for data_idx, title in ((0, "Path"), (2, "Type")):
            tvcolumn = gtk.TreeViewColumn(title)
            tvcolumn.set_resizable(True)
            self.treeview.append_column(tvcolumn)
            cell = gtk.CellRendererText()
            tvcolumn.pack_start(cell, True)
            tvcolumn.add_attribute(cell, 'text', data_idx)

        self.update_tree()

        self.treeview.show()
        scrolled_win=gtk.ScrolledWindow()
        scrolled_win.add_with_viewport(self.treeview)
        scrolled_win.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        scrolled_win.show()
        vbox.pack_start(scrolled_win)
        vbox.show()

        self.main_window.show()
        
        gtk.main()

if __name__=="__main__":
    GtkStorageFrontend().run()
