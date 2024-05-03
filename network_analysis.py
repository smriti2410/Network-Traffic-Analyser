import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
import time
import joblib
from scapy.all import sniff, TCP, Raw

# Load the dataset
data = pd.read_csv('/Users/smritikaushal/Desktop/Projects/NetworkAnalyser/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv')

# Select 10 most important features
selected_features = [' Destination Port', ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets', 
                     ' Total Length of Bwd Packets', ' Fwd Packet Length Max', ' Fwd Packet Length Min', 
                     ' Fwd Packet Length Mean', ' Fwd Packet Length Std']

# Ensure the features and labels are correctly selected
X = data[selected_features]
y = data[' Label']

# Handle NaNs and infinite values
X = X.dropna()  # Drop rows with NaNs
X = X.replace([float('inf'), -float('inf')], 1e12)  # Replace infinite values

# Split the dataset into training and testing sets (no need to do it again)
# Standardize the features
scaler = StandardScaler()
X = scaler.fit_transform(X)

# Initialize the Random Forest model
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)

# Train the model (no need to do it again)
rf_model.fit(X, y)

# Save the trained model (no need to do it again)
joblib.dump(rf_model, 'random_forest_model.pkl')

# Initialize a variable to store the source port
src_port = 80

# Initialize a list to store the extracted packet data
packet_data = []

# Start time for capturing network traffic
start_time = time.time()

# Function to process each packet and extract relevant information
def process_packet(packet):
    global packet_data

    try:
        if TCP in packet:
            # Extract relevant fields from the packet
            dst_port = packet[TCP].dport
            flow_duration = packet.time - start_time
            total_fwd_packets = 1 if packet[TCP].sport == src_port else 0
            total_bwd_packets = 1 if packet[TCP].dport == src_port else 0
            total_fwd_length = len(packet[Raw].load) if Raw in packet else 0
            total_bwd_length = 0
            fwd_packet_length_max = len(packet)
            fwd_packet_length_min = len(packet)
            fwd_packet_length_mean = len(packet)
            fwd_packet_length_std = 0

            # Append the extracted packet data to a list of dictionaries
            packet_data.append({
                ' Destination Port': dst_port,
                ' Flow Duration': flow_duration,
                ' Total Fwd Packets': total_fwd_packets,
                ' Total Backward Packets': total_bwd_packets,
                ' Total Length of Bwd Packets': total_bwd_length,
                ' Fwd Packet Length Max': fwd_packet_length_max,
                ' Fwd Packet Length Min': fwd_packet_length_min,
                ' Fwd Packet Length Mean': fwd_packet_length_mean,
                ' Fwd Packet Length Std': fwd_packet_length_std
            })

    except Exception as e:
        print(f"Error processing packet: {e}")

# Sniff network traffic and process each packet for 5 seconds
print("Capturing network traffic for 5 seconds on all interfaces")
sniff(prn=process_packet, timeout=5)

# Convert the list of dictionaries to a DataFrame
network_traffic_data = pd.DataFrame(packet_data)

# Preprocess the network traffic data
network_traffic_data_standardized = scaler.transform(network_traffic_data)

# Use the trained Random Forest model to predict whether the network traffic data packets are malicious
print("Making predictions...")
predictions = rf_model.predict(network_traffic_data_standardized)

# Generate alerts for malicious data packets
print("Generating alerts for malicious data packets...")
malicious_indices = [i for i, prediction in enumerate(predictions) if prediction == 1]
print(f"Alert generation completed. Total {len(malicious_indices)} malicious data packets detected.")
