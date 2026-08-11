# encoding: utf-8
from burp import IBurpExtender, IHttpListener, IExtensionStateListener, ITab
from javax.swing import (JPanel, JButton, JFileChooser, JTextPane, JScrollPane, JOptionPane,
                         JCheckBox, JLabel, JTextField, JTabbedPane, BorderFactory, JSpinner,
                         SpinnerNumberModel, UIManager, JTextArea, SwingUtilities)
from java.awt import BorderLayout, Dimension, Font, GridBagLayout, GridBagConstraints, Insets, FlowLayout
from java.io import FileOutputStream, OutputStreamWriter, BufferedWriter, File
from java.nio.charset import Charset
from java.util import Timer, TimerTask, WeakHashMap
from java.util.concurrent import locks, LinkedBlockingQueue, TimeUnit
from java.lang import Thread, Runnable, System
import datetime, os


class BurpExtender(IBurpExtender, IHttpListener, IExtensionStateListener, ITab):

    # Placeholder for the Status Code / End Time columns of a request that has
    # been logged but whose response has not arrived (or never will).
    PENDING = "-"

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("SAVER_LOGGER")

        self._callbacks.registerHttpListener(self)
        self._callbacks.registerExtensionStateListener(self)

        # Thread-safe data storage with lock
        self.log_data = []
        self.request_counter = 0
        self.url_request_counts = {}  # O(1) per-URL counts (guarded by data_lock)
        self.runtime_id = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        self.data_lock = locks.ReentrantLock()  # Thread safety for log_data
        
        # Request tracking for insertion points and timing, keyed weakly by
        # the message object: an entry lives exactly as long as Burp holds
        # the message, so it cannot leak and cannot be evicted while a
        # response is still possible.
        self.request_tracking = WeakHashMap()
        self.tracking_lock = locks.ReentrantLock()  # Thread safety for tracking

        # Settings
        self.auto_backup_enabled = True
        self.backup_folder = os.path.join(os.path.expanduser("~"), "Desktop")
        self.backup_interval_seconds = 60
        self.backup_timer = None
        self.last_backup_time = 0  # Track last backup to prevent over-firing

        # Processing queue and worker thread; the blocking queue does its
        # own synchronization, no separate lock needed
        self.processing_queue = LinkedBlockingQueue()
        self.worker_thread = None
        self.shutdown_flag = False

        self._init_ui()
        self._callbacks.addSuiteTab(self)
        self._start_worker_thread()
        self._start_backup_scheduler()

    # ------------- WORKER THREAD FOR PROCESSING ------------- #

    def _start_worker_thread(self):
        """Start background worker thread for processing requests"""
        self.shutdown_flag = False
        
        class Worker(Runnable):
            def __init__(self, extender):
                self.extender = extender
            
            def run(self):
                while not self.extender.shutdown_flag:
                    try:
                        # Block until work arrives; time out periodically so
                        # the shutdown flag is rechecked
                        work_item = self.extender.processing_queue.poll(
                            500, TimeUnit.MILLISECONDS)
                        if work_item is not None:
                            self.extender._process_request_data(work_item)
                    except Exception as e:
                        print("[SAVER_LOGGER] Worker thread error: %s" % str(e))
        
        self.worker_thread = Thread(Worker(self))
        self.worker_thread.setDaemon(True)
        self.worker_thread.start()

    def _process_request_data(self, work_item):
        """Process request data in background thread"""
        try:
            tool_flag = work_item['tool_flag']
            message_info = work_item['message_info']
            is_request = work_item['is_request']
            
            if is_request:
                self._handle_request(tool_flag, message_info)
            else:
                self._handle_response(tool_flag, message_info)
        except Exception as e:
            print("[SAVER_LOGGER] Processing error: %s" % str(e))

    # ------------- UI ------------- #

    def _init_ui(self):
        self.panel = JPanel(BorderLayout())
        self.tabs = JTabbedPane()

        self._build_dashboard_tab()
        self._build_settings_tab()

        self.panel.add(self.tabs, BorderLayout.CENTER)

    def _build_dashboard_tab(self):
        dash = JPanel(BorderLayout())
        dash.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        header = JPanel(FlowLayout(FlowLayout.LEFT))
        title = JLabel("SAVER_LOGGER - Store All Logs")
        title.setFont(Font("Arial", Font.BOLD, 24))
        header.add(title)
        dash.add(header, BorderLayout.NORTH)

        btn_panel = JPanel(FlowLayout(FlowLayout.CENTER, 10, 10))

        export_btn = JButton("Export CSV")
        export_btn.setPreferredSize(Dimension(140, 35))
        export_btn.addActionListener(self.export_csv_manual)
        btn_panel.add(export_btn)

        backup_btn = JButton("Backup Now")
        backup_btn.setPreferredSize(Dimension(140, 35))
        backup_btn.addActionListener(self.backup_now)
        btn_panel.add(backup_btn)

        clear_btn = JButton("Clear Logs")
        clear_btn.setPreferredSize(Dimension(140, 35))
        clear_btn.addActionListener(self.clear_logs)
        btn_panel.add(clear_btn)

        dash.add(btn_panel, BorderLayout.CENTER)

        info = JTextPane()
        info.setContentType("text/html")
        info.setEditable(False)
        info.setBackground(UIManager.getColor("Panel.background"))
        info.setText("""
        <html><body style='font-family: Arial; font-size: 12px;'>
        <h3 style='color:#ff6600;font-size: 18px;'>Extension Info</h3>
        <ul>
        <li>Logs HTTP requests from all Burp tools</li>
        <li>Tracks insertion points, request counts, and timing</li>
        <li>Thread-safe background processing</li>
        <li>Auto-saves log file on crash / closures</li>
        <li>Manual export & backup supported</li>
        <li>Interval-based auto-backups to custom path</li>
        </ul>
        <p><b>Author:</b> Sachhit Anasane</p>
        <p><b>Session ID:</b> %s</p>
        </body></html>
        """ % self.runtime_id)

        dash.add(JScrollPane(info), BorderLayout.SOUTH)

        self.tabs.addTab("Dashboard", dash)

    def _build_settings_tab(self):
        settings = JPanel(BorderLayout())
        settings.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        config = JPanel(GridBagLayout())
        config.setBorder(BorderFactory.createTitledBorder("Backup Configuration"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = gbc.WEST

        self.enable_backup = JCheckBox("Enable Automatic Backup", True)

        self.interval_spinner = JSpinner(SpinnerNumberModel(60, 10, 3600, 10))
        self.interval_spinner.setPreferredSize(Dimension(90, 25))

        self.folder_input = JTextField(os.path.join(os.path.expanduser("~"), "Desktop"), 30)
        browse = JButton("Browse")
        browse.addActionListener(self.select_folder)

        save = JButton("Save Settings")
        save.addActionListener(self.save_settings)

        # UI placement
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2
        config.add(self.enable_backup, gbc)

        gbc.gridy = 1; gbc.gridwidth = 1
        config.add(JLabel("Backup Interval (seconds):"), gbc)
        gbc.gridx = 1
        config.add(self.interval_spinner, gbc)

        gbc.gridx = 0; gbc.gridy = 2
        config.add(JLabel("Backup Folder:"), gbc)
        gbc.gridx = 1
        config.add(self.folder_input, gbc)
        gbc.gridx = 2
        config.add(browse, gbc)

        gbc.gridx = 0; gbc.gridy = 3; gbc.gridwidth = 3
        config.add(save, gbc)

        settings.add(config, BorderLayout.NORTH)

        self.status_area = JTextArea(12, 50)
        self.status_area.setEditable(False)
        self.status_area.append("Extension Loaded\n")
        self.status_area.append("Auto-backup ready\n")
        self.status_area.append("HTTP logging active\n")
        self.status_area.append("Background worker thread started\n")
        self.status_area.append("Backup location: " + self.backup_folder + "\n")
        settings.add(JScrollPane(self.status_area), BorderLayout.CENTER)

        self.tabs.addTab("Settings", settings)

    # ------------- SETTINGS ACTIONS ------------- #

    def select_folder(self, event):
        ch = JFileChooser()
        ch.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        ch.setCurrentDirectory(File(self.backup_folder))
        if ch.showOpenDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            self.folder_input.setText(ch.getSelectedFile().getAbsolutePath())

    def save_settings(self, event):
        self.auto_backup_enabled = self.enable_backup.isSelected()
        self.backup_folder = self.folder_input.getText()
        self.backup_interval_seconds = int(self.interval_spinner.getValue())
        
        self._start_backup_scheduler()
        
        self._append_status("\n[%s] Settings saved!" % datetime.datetime.now().strftime('%H:%M:%S'))
        self._append_status("\n  - Auto-backup: %s" % ("Enabled" if self.auto_backup_enabled else "Disabled"))
        self._append_status("\n  - Interval: %d seconds" % self.backup_interval_seconds)
        self._append_status("\n  - Location: %s\n" % self.backup_folder)
        
        JOptionPane.showMessageDialog(self.panel, "Settings saved successfully!")

    def _append_status(self, text):
        """Thread-safe status area update"""
        class StatusUpdater(Runnable):
            def __init__(self, status_area, message):
                self.status_area = status_area
                self.message = message
            
            def run(self):
                self.status_area.append(self.message)
        
        SwingUtilities.invokeLater(StatusUpdater(self.status_area, text))

    # ------------- BACKUP SCHEDULER ------------- #

    def _start_backup_scheduler(self):
        if self.backup_timer:
            self.backup_timer.cancel()

        if not self.auto_backup_enabled:
            self._append_status("\n[%s] Auto-backup disabled" % datetime.datetime.now().strftime('%H:%M:%S'))
            return

        self.backup_timer = Timer("SAVER_LOGGER_AutoSave", True)

        class Task(TimerTask):
            def __init__(self, extender):
                self.extender = extender
            
            def run(self):
                if self.extender.auto_backup_enabled:
                    # Check if enough time has passed since last backup
                    current_time = System.currentTimeMillis() / 1000
                    if (current_time - self.extender.last_backup_time) >= self.extender.backup_interval_seconds:
                        self.extender._auto_backup()
                        self.extender.last_backup_time = current_time

        delay = 10000  # 10 seconds initial delay
        period = self.backup_interval_seconds * 1000
        self.backup_timer.schedule(Task(self), delay, period)
        
        self._append_status("\n[%s] Auto-backup scheduler started (every %ds)" % 
                                (datetime.datetime.now().strftime('%H:%M:%S'), self.backup_interval_seconds))

    # ------------- HTTP LOGGING ------------- #

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        High-volume method - offload processing to background thread
        """
        # Queue work item for background processing
        work_item = {
            'tool_flag': toolFlag,
            'message_info': messageInfo,
            'is_request': messageIsRequest
        }

        self.processing_queue.put(work_item)

    def _new_log_row(self, messageInfo, req, toolFlag, status, start_time, end_time):
        """Build and append a log row, assigning the serial and per-URL count
        under a single data_lock hold (so a concurrent clear_logs cannot
        interleave), and return the row for later in-place updates."""
        url = str(req.getUrl())
        host = messageInfo.getHttpService().getHost()
        method = req.getMethod()
        tool = self._callbacks.getToolName(toolFlag)
        insertion_points = self._count_insertion_points(req, messageInfo.getRequest(), tool)

        self.data_lock.lock()
        try:
            self.request_counter += 1
            serial = self.request_counter

            # Count how many times this URL has been requested (O(1) instead
            # of scanning the whole log on every message)
            request_count = self.url_request_counts.get(url, 0) + 1
            self.url_request_counts[url] = request_count

            row = [
                serial,             # Serial No
                host,               # Host
                method,             # Request Method
                url,                # URL
                status,             # Status Code
                tool,               # Tool Name
                request_count,      # Request Count
                insertion_points,   # Insertion Point Count
                start_time,         # Start Time
                end_time            # End Time
            ]
            self.log_data.append(row)
        finally:
            self.data_lock.unlock()
        return row

    def _handle_request(self, toolFlag, messageInfo):
        """Log every request as its own row immediately, so a request is
        recorded even if no response ever arrives. The matching response
        fills in the status and end time later."""
        req = self._helpers.analyzeRequest(messageInfo)
        start_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        row = self._new_log_row(messageInfo, req, toolFlag,
                                self.PENDING, start_time, self.PENDING)

        # Remember the row (keyed weakly by the message) so this request's
        # response can fill it in when it arrives.
        self.tracking_lock.lock()
        try:
            self.request_tracking.put(messageInfo, row)
        finally:
            self.tracking_lock.unlock()

    def _handle_response(self, toolFlag, messageInfo):
        """Fill in the status and end time on the row created for this
        message's request. If there is no such row (a response with no request
        event), log the response as its own row so it is not lost."""
        res_bytes = messageInfo.getResponse()
        status = self.PENDING
        if res_bytes:
            try:
                res = self._helpers.analyzeResponse(res_bytes)
                status = str(res.getStatusCode())
            except:
                status = "Error"

        end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Match this response to its own request via the message object
        self.tracking_lock.lock()
        try:
            row = self.request_tracking.remove(messageInfo)
        finally:
            self.tracking_lock.unlock()

        if row is not None:
            # Update the existing request row in place.
            self.data_lock.lock()
            try:
                row[4] = status      # Status Code
                row[9] = end_time    # End Time
            finally:
                self.data_lock.unlock()
        else:
            # No request row for this message: log the response on its own.
            req = self._helpers.analyzeRequest(messageInfo)
            self._new_log_row(messageInfo, req, toolFlag, status, end_time, end_time)

    def _count_insertion_points(self, req, request_bytes, tool):
        """
        Count insertion points based on tool and request analysis.
        Note: Intruder removes § markers before sending, so we count parameters instead.
        """
        insertion_point_count = 0
        
        try:
            # For all tools: count parameters as potential insertion points
            params = req.getParameters()
            if params:
                insertion_point_count = len(params)
                
        except Exception as e:
            insertion_point_count = 0
        
        return insertion_point_count

    # ------------- EXPORT + BACKUP ------------- #

    def _ensure_backup_folder(self, folder):
        """
        Create the backup folder if it does not exist (the default, Desktop,
        is absent on many Linux/headless systems). Returns True when the
        folder is usable; failures are reported instead of being silent.
        """
        if os.path.isdir(folder):
            return True
        try:
            os.makedirs(folder)
            self._append_status("\n[%s] Created backup folder: %s" %
                                (datetime.datetime.now().strftime('%H:%M:%S'), folder))
            return True
        except OSError as e:
            print("[SAVER_LOGGER] Backup folder unavailable: %s (%s)" % (folder, str(e)))
            self._append_status("\n[%s] Backup folder unavailable: %s" %
                                (datetime.datetime.now().strftime('%H:%M:%S'), folder))
            return False

    def backup_now(self, event):
        """Manual backup button - saves to configured backup folder with timestamp"""
        self.data_lock.lock()
        try:
            has_data = len(self.log_data) > 0
        finally:
            self.data_lock.unlock()

        if not has_data:
            JOptionPane.showMessageDialog(self.panel, "No data to back up!")
            return

        if not self._ensure_backup_folder(self.backup_folder):
            JOptionPane.showMessageDialog(self.panel,
                                          "Backup failed! Folder unavailable:\n%s" % self.backup_folder)
            return

        timestamp = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
        filename = "SAVER_LOGGER_BACKUP_%s.csv" % timestamp
        filepath = os.path.join(self.backup_folder, filename)

        result = self._write_full_csv(filepath)
        if result:
            count = 0
            self.data_lock.lock()
            try:
                count = len(self.log_data)
            finally:
                self.data_lock.unlock()
            
            self._append_status("\n[%s] Manual backup completed: %d requests" % 
                                    (datetime.datetime.now().strftime('%H:%M:%S'), count))
            JOptionPane.showMessageDialog(self.panel, 
                                          "Backup completed successfully!\n%d requests saved to:\n%s" % 
                                          (count, filepath))
        else:
            JOptionPane.showMessageDialog(self.panel, "Backup failed! Check console for errors.")

    def _auto_backup(self):
        """Automatic backup triggered by timer - overwrites same file"""
        self.data_lock.lock()
        try:
            has_data = len(self.log_data) > 0
        finally:
            self.data_lock.unlock()
        
        if not has_data:
            return

        if not self._ensure_backup_folder(self.backup_folder):
            return

        # Auto-backup uses a consistent filename (overwrites each time)
        filename = "SAVER_LOGGER_AUTOSAVE.csv"
        filepath = os.path.join(self.backup_folder, filename)

        result = self._write_full_csv(filepath)
        if result:
            count = 0
            self.data_lock.lock()
            try:
                count = len(self.log_data)
            finally:
                self.data_lock.unlock()

            self._append_status("\n[%s] Auto-backup: %d requests saved" %
                                    (datetime.datetime.now().strftime('%H:%M:%S'), count))
        else:
            self._append_status("\n[%s] Auto-backup FAILED - check extension console" %
                                    datetime.datetime.now().strftime('%H:%M:%S'))

    def export_csv_manual(self, event):
        """Manual CSV export with file chooser"""
        self.data_lock.lock()
        try:
            has_data = len(self.log_data) > 0
        finally:
            self.data_lock.unlock()
        
        if not has_data:
            JOptionPane.showMessageDialog(self.panel, "No data to export!")
            return

        ch = JFileChooser()
        ch.setSelectedFile(File("SAVER_LOGGER_Export_%s.csv" % 
                                datetime.datetime.now().strftime('%Y%m%d_%H%M%S')))
        
        if ch.showSaveDialog(self.panel) == JFileChooser.APPROVE_OPTION:
            filepath = ch.getSelectedFile().getAbsolutePath()
            if not filepath.endswith('.csv'):
                filepath += '.csv'
            
            result = self._write_full_csv(filepath)
            if result:
                count = 0
                self.data_lock.lock()
                try:
                    count = len(self.log_data)
                finally:
                    self.data_lock.unlock()
                
                JOptionPane.showMessageDialog(self.panel, 
                                              "Export successful!\n%d requests saved to:\n%s" % 
                                              (count, filepath))
            else:
                JOptionPane.showMessageDialog(self.panel, "Export failed! Check console for errors.")

    def _csv_field(self, value):
        """
        Encode one CSV field per RFC 4180 so field contents survive the
        export unmodified, with spreadsheet formula-injection protection:
        a field beginning with a formula trigger character is prefixed
        with a single quote so Excel/LibreOffice treat it as text.
        """
        text = u"%s" % value
        if len(text) > 1 and text[0] in (u'=', u'+', u'-', u'@', u'\t'):
            text = u"'" + text
        text = text.replace(u"\n", u" ").replace(u"\r", u" ")
        if u',' in text or u'"' in text:
            text = u'"' + text.replace(u'"', u'""') + u'"'
        return text

    def _write_full_csv(self, filepath):
        """
        Write ALL log data to a single CSV file with complete column structure.
        Thread-safe implementation.
        """
        self.data_lock.lock()
        try:
            if not self.log_data:
                return False

            # Snapshot copies of each row, so a response updating a row's
            # status/end time in place cannot change the export mid-write.
            data_snapshot = [list(row) for row in self.log_data]
        finally:
            self.data_lock.unlock()

        fos = None
        writer = None
        try:
            # Always overwrite with complete data (not append)
            fos = FileOutputStream(filepath, False)  # False = overwrite
            writer = BufferedWriter(OutputStreamWriter(fos, Charset.forName("UTF-8")))

            # Header metadata
            writer.write("# Generated By: SAVER_LOGGER\n")
            writer.write("# Session ID: %s\n" % self.runtime_id)
            writer.write("# Export Time: %s\n" % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            writer.write("# Total Requests: %d\n\n" % len(data_snapshot))

            # Column headers
            writer.write("Serial No,Host,Request Method,URL,Status Code,Tool Name,Request Count,Insertion Point Count,Start Time,End Time\n")

            # Write ALL data rows
            for row in data_snapshot:
                writer.write(u",".join([self._csv_field(col) for col in row]) + u"\n")

            # Footer metadata for authenticity
            writer.write("\n# --- FOOTER METADATA ---\n")
            writer.write("# Burp Suite Version: %s\n" % " ".join(self._callbacks.getBurpVersion()))
            writer.write("# Exported: %s\n" % datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            writer.write("# Runtime ID: %s\n" % self.runtime_id)
            writer.write("# Total Requests Logged: %d\n" % len(data_snapshot))

            return True

        except Exception as e:
            print("[SAVER_LOGGER] Export failed: %s" % str(e))
            import traceback
            traceback.print_exc()
            return False

        finally:
            # Close on every path; BufferedWriter.close() flushes first
            try:
                if writer is not None:
                    writer.close()
                elif fos is not None:
                    fos.close()
            except Exception:
                pass

    def clear_logs(self, event):
        """Clear all logged data with confirmation"""
        self.data_lock.lock()
        try:
            count = len(self.log_data)
        finally:
            self.data_lock.unlock()
        
        confirm = JOptionPane.showConfirmDialog(
            self.panel,
            "Are you sure you want to clear all %d logged requests?" % count,
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        
        if confirm == JOptionPane.YES_OPTION:
            self.data_lock.lock()
            try:
                cleared_count = len(self.log_data)
                self.log_data = []
                self.request_counter = 0
                self.url_request_counts = {}
            finally:
                self.data_lock.unlock()
            
            self.tracking_lock.lock()
            try:
                self.request_tracking = WeakHashMap()
            finally:
                self.tracking_lock.unlock()
            
            self._append_status("\n[%s] All logs cleared (%d requests removed)" % 
                                    (datetime.datetime.now().strftime('%H:%M:%S'), cleared_count))
            JOptionPane.showMessageDialog(self.panel, "Logs cleared successfully!")

    # ------------- TAB INTERFACE ------------- #

    def getTabCaption(self):
        return "SAVER_LOGGER"

    def getUiComponent(self):
        return self.panel

    # ------------- CLEANUP & EXIT HANDLER ------------- #

    def extensionUnloaded(self):
        """
        Called when extension is unloaded or Burp closes/crashes.
        Performs final backup with timestamped filename.
        """
        # Shutdown worker thread
        self.shutdown_flag = True
        worker_stopped = True
        if self.worker_thread:
            try:
                self.worker_thread.join(5000)  # Wait up to 5 seconds
            except:
                pass
            try:
                worker_stopped = not self.worker_thread.isAlive()
            except:
                worker_stopped = True

        # Cancel backup timer
        if self.backup_timer:
            self.backup_timer.cancel()

        # Drain anything the worker had not gotten to so the exit backup
        # includes messages queued right up to shutdown. Only drain once the
        # worker has actually stopped, so this is the sole consumer of the
        # queue and never races the worker.
        if worker_stopped:
            drain = lambda: self.processing_queue.poll(0, TimeUnit.MILLISECONDS)
            for work_item in iter(drain, None):
                self._process_request_data(work_item)
        else:
            print("[SAVER_LOGGER] Worker still active at unload; "
                  "some queued messages may be unprocessed")

        # Final backup on exit with timestamp
        self.data_lock.lock()
        try:
            has_data = len(self.log_data) > 0
        finally:
            self.data_lock.unlock()
        
        if has_data and self._ensure_backup_folder(self.backup_folder):
            timestamp = datetime.datetime.now().strftime('%d%m%Y_%H%M%S')
            filename = "SAVER_LOGGER_AUTOSAVE_%s.csv" % timestamp
            filepath = os.path.join(self.backup_folder, filename)

            self._write_full_csv(filepath)
            
            self.data_lock.lock()
            try:
                count = len(self.log_data)
            finally:
                self.data_lock.unlock()
            
            print("[SAVER_LOGGER] Exit backup completed: %d requests saved to %s" % (count, filepath))
        else:
            print("[SAVER_LOGGER] Extension unloaded (no data to save)")
