import PySimpleGUI as sg

# Define the layout
layout = [
    [sg.Text("Grouped Widgets")],
    [sg.Button("Button 1"), sg.Button("Button 2")],
    [sg.InputText("Input 1"), sg.InputText("Input 2")],
    [sg.Checkbox("Checkbox 1"), sg.Checkbox("Checkbox 2")],
    [sg.Button("OK"), sg.Button("Cancel")]
]

# Create the window
window = sg.Window("Widget Grouping Example", layout)

# Event loop
while True:
    event, values = window.read()

    # Handle events
    if event == sg.WINDOW_CLOSED or event == "Cancel":
        break
    elif event == "OK":
        print("Button OK pressed")

# Close the window
window.close()
