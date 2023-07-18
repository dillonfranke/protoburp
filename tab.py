from burp import ITab
from javax.swing import JSplitPane, JScrollPane, JPanel, JButton, BoxLayout, Box
from javax.swing import JLabel, JCheckBox, JTextArea, JList, ListSelectionModel, JFileChooser
from javax.swing import DefaultListModel
from javax.swing.border import EmptyBorder
from java.awt import Component, Dimension, BorderLayout

class Tab(ITab):
    """Burp tab for selecting a compile Protobuf file and enabling/disabling the extension"""

    def __init__(self, extension, burp_callbacks):
        self.protoburp_enabled = False
        self._burp_callbacks = burp_callbacks
        self._extension = extension
        self.selectedFilePath = None

        self._type_list_component = JList(DefaultListModel())
        self._type_list_component.setSelectionMode(
            ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
        )

        self._component = JPanel()
        self._component.setLayout(BorderLayout())
        self._component.setBorder(EmptyBorder(10, 10, 10, 10))

        # Add instruction label
        instructionText = """
        Welcome to ProtoBurp! ProtoBurp converts JSON data into Protobuf messages based on a provided `.proto` file. This allows you to use Repeater or Intruder to quickly fuzz endpoints accepting Protobufs.
        
        To use this extension, please follow the steps below:
          1. Create or obtain a `.proto` file you'd like to create protobuf messages
          2. Use the `protoc` utility to compile your `.proto` file into Python format. (e.g. `protoc --python_out=./ MyMessage.proto`)
          3. Click the 'Choose File' button to select your compiled protobuf file.
          4. Check the 'Enable ProtoBurp' checkbox.
          5. All requests sent with the header `ProtoBurp: True` will then be converted from JSON to a Protobuf!
        
        For more information, please see my blog post here: https://dillonfrankesecurity.com
        """
        instructions = JTextArea(instructionText)
        instructions.setEditable(False)  # Make the text area non-editable
        self._component.add(instructions, BorderLayout.PAGE_START)

        # Add file chooser button and checkbox
        topPanel = JTextArea()
        topPanel.setLayout(BoxLayout(topPanel, BoxLayout.Y_AXIS))  # Arrange components vertically

        fileLabel = JLabel("Compiled Protobuf File (Python Format): ")
        button = JButton("Choose File", actionPerformed=self.chooseFile)
        fileChooserPanel = JPanel()  # A new panel to hold the file chooser components
        fileChooserPanel.add(fileLabel)
        fileChooserPanel.add(button)
        self._label = JLabel("No file chosen")
        fileChooserPanel.add(self._label)

        # Add option to enable/disable ProtoBurp
        enableProtoBurp = JCheckBox("Enable ProtoBurp", actionPerformed=self.toggleEnabled)

        topPanel.add(enableProtoBurp)
        topPanel.add(fileChooserPanel)
        

        self._component.add(topPanel, BorderLayout.CENTER)

    def toggleEnabled(self, event):
        self.protoburp_enabled = not self.protoburp_enabled
        print(self.protoburp_enabled)

    def chooseFile(self, event):
        chooser = JFileChooser()
        action = chooser.showOpenDialog(None)

        if action == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            self.selectedFilePath = file.getAbsolutePath()
            self._label.text = "Selected file: " + self.selectedFilePath
            print("Selected file: " + self.selectedFilePath)

    def getTabCaption(self):
        """Returns name on tab"""
        return "ProtoBurp"

    def getUiComponent(self):
        """Returns Java AWT component for tab"""
        return self._component
