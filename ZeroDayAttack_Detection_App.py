import numpy as np
import pandas as pd
import pickle
import streamlit as st
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import plotly.express as px
import requests

# Load the saved model and preprocessing objects
with open('scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)
with open('pca.pkl', 'rb') as f:
    pca = pickle.load(f)
with open('ae.pkl', 'rb') as f):
    autoencoder = pickle.load(f)

@st.cache(allow_output_mutation=True)
def load_model(url):
    response = requests.get(url)
    return pickle.loads(response.content)

model_url = "https://drive.google.com/file/d/1suX7Ooz0eMd5r0hTeUiEKLg9gklGfDna/view?usp=drive_link"  
best_if_model = load_model(model_url)

# Function for zero-day attack detection
def zerodayattack_prediction(input_data):
    try:
        # Convert input data to numpy array
        input_data_as_numpy_array = np.asarray(input_data)
        input_data_reshaped = input_data_as_numpy_array.reshape(len(input_data_as_numpy_array), -1)

        # Scale the input data
        input_data_scaled = scaler.transform(input_data_reshaped)

        # Apply PCA transformation
        input_data_pca = pca.transform(input_data_scaled)

        # Extract features using the trained Autoencoder
        extracted_features = autoencoder.predict(input_data_pca)

        # Use Isolation Forest for final prediction
        prediction = best_if_model.predict(extracted_features)

        # Convert predictions to readable format
        result = ['Benign' if pred == 1 else 'Attack' for pred in prediction]
        return result
    except Exception as e:
        return str(e)

def main():
    st.title("Zero-Day Attack Detection System")

    # Display an image 
    image_path = "image/picc.jpg"
    st.image(image_path, use_column_width=True)

    # Choose mode: Batch Prediction or Manual Input
    mode = st.radio("Select Mode", ("Batch Prediction", "Manual Input"))

    if mode == "Batch Prediction":
        uploaded_file = st.file_uploader("Upload CSV file", type=["csv"])
        
        if uploaded_file is not None:
            input_df = pd.read_csv(uploaded_file)
            
            if input_df.isnull().values.any():
                st.warning("Error occurred. Please check your file for missing values.")
                return
            
            if st.button("Predict"):
                with st.spinner("Processing..."):
                    true_labels = input_df['Label']  # Assuming the true labels are in a 'Label' column
                    input_data = input_df.drop(columns=['Label']).values  # Remove label column before prediction
                    
                    predictions = zerodayattack_prediction(input_data)
                    predicted_labels = [1 if pred == 'Attack' else 0 for pred in predictions]
                    
                    accuracy = accuracy_score(true_labels, predicted_labels)
                    precision = precision_score(true_labels, predicted_labels)
                    recall = recall_score(true_labels, predicted_labels)
                    f1 = f1_score(true_labels, predicted_labels)
                
                st.success("Predictions Complete!")
                st.write(f"**Accuracy:** {accuracy * 100:.2f}%")
                st.write(f"**Precision:** {precision:.2f}")
                st.write(f"**Recall:** {recall:.2f}")
                st.write(f"**F1 Score:** {f1:.2f}")
                
                input_df['Prediction'] = predictions
                st.write(input_df)

                # Visualization
                fig = px.histogram(input_df, x='Prediction', title='Benign vs Attack Instances')
                st.plotly_chart(fig)

                # Download prediction results
                st.download_button(
                    label="Download Predictions Result",
                    data=input_df.to_csv().encode('utf-8'),
                    file_name='predictions.csv',
                    mime='text/csv'
                )

    elif mode == "Manual Input":
        # Input fields for manual prediction (49 fields)
        dest_port = st.text_input("Destination Port", "Type Here")
        flow_duration = st.text_input("Flow Duration", "Type Here")
        total_fwd_packets = st.text_input("Total Fwd Packets", "Type Here")
        total_len_fwd_packets = st.text_input("Total Length of Fwd Packets", "Type Here")
        fwd_pkt_len_max = st.text_input("Fwd Packet Length Max", "Type Here")
        fwd_pkt_len_min = st.text_input("Fwd Packet Length Min", "Type Here")
        fwd_pkt_len_mean = st.text_input("Fwd Packet Length Mean", "Type Here")
        bwd_pkt_len_max = st.text_input("Bwd Packet Length Max", "Type Here")
        bwd_pkt_len_min = st.text_input("Bwd Packet Length Min", "Type Here")
        flow_bytes_per_s = st.text_input("Flow Bytes/s", "Type Here")
        flow_pkts_per_s = st.text_input("Flow Packets/s", "Type Here")
        flow_iat_mean = st.text_input("Flow IAT Mean", "Type Here")
        flow_iat_std = st.text_input("Flow IAT Std", "Type Here")
        flow_iat_max = st.text_input("Flow IAT Max", "Type Here")
        flow_iat_min = st.text_input("Flow IAT Min", "Type Here")
        fwd_iat_mean = st.text_input("Fwd IAT Mean", "Type Here")
        fwd_iat_std = st.text_input("Fwd IAT Std", "Type Here")
        fwd_iat_min = st.text_input("Fwd IAT Min", "Type Here")
        bwd_iat_total = st.text_input("Bwd IAT Total", "Type Here")
        bwd_iat_mean = st.text_input("Bwd IAT Mean", "Type Here")
        bwd_iat_std = st.text_input("Bwd IAT Std", "Type Here")
        bwd_iat_max = st.text_input("Bwd IAT Max", "Type Here")
        bwd_iat_min = st.text_input("Bwd IAT Min", "Type Here")
        fwd_psh_flags = st.text_input("Fwd PSH Flags", "Type Here")
        fwd_urg_flags = st.text_input("Fwd URG Flags", "Type Here")
        fwd_header_len = st.text_input("Fwd Header Length", "Type Here")
        bwd_header_len = st.text_input("Bwd Header Length", "Type Here")
        bwd_pkts_per_s = st.text_input("Bwd Packets/s", "Type Here")
        min_pkt_len = st.text_input("Min Packet Length", "Type Here")
        max_pkt_len = st.text_input("Max Packet Length", "Type Here")
        pkt_len_mean = st.text_input("Packet Length Mean", "Type Here")
        pkt_len_var = st.text_input("Packet Length Variance", "Type Here")
        fin_flag_count = st.text_input("FIN Flag Count", "Type Here")
        rst_flag_count = st.text_input("RST Flag Count", "Type Here")
        psh_flag_count = st.text_input("PSH Flag Count", "Type Here")
        ack_flag_count = st.text_input("ACK Flag Count", "Type Here")
        urg_flag_count = st.text_input("URG Flag Count", "Type Here")
        down_up_ratio = st.text_input("Down/Up Ratio", "Type Here")
        init_win_bytes_fwd = st.text_input("Init_Win_bytes_forward", "Type Here")
        init_win_bytes_bwd = st.text_input("Init_Win_bytes_backward", "Type Here")
        act_data_pkt_fwd = st.text_input("act_data_pkt_fwd", "Type Here")
        min_seg_size_fwd = st.text_input("min_seg_size_forward", "Type Here")
        active_mean = st.text_input("Active Mean", "Type Here")
        active_std = st.text_input("Active Std", "Type Here")
        active_max = st.text_input("Active Max", "Type Here")
        active_min = st.text_input("Active Min", "Type Here")
        idle_std = st.text_input("Idle Std", "Type Here")
        has_inf_flow_bytes = st.text_input("Has Infinite Flow Bytes", "Type Here")
        has_inf_flow_pkts = st.text_input("Has Infinite Flow Packets", "Type Here")

        # Collect input data into a list
        input_data = [[dest_port, flow_duration, total_fwd_packets, total_len_fwd_packets, fwd_pkt_len_max, 
                       fwd_pkt_len_min, fwd_pkt_len_mean, bwd_pkt_len_max, bwd_pkt_len_min, flow_bytes_per_s, 
                       flow_pkts_per_s, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min, fwd_iat_mean, 
                       fwd_iat_std, fwd_iat_min, bwd_iat_total, bwd_iat_mean, bwd_iat_std, bwd_iat_max, 
                       bwd_iat_min, fwd_psh_flags, fwd_urg_flags, fwd_header_len, bwd_header_len, bwd_pkts_per_s, 
                       min_pkt_len, max_pkt_len, pkt_len_mean, pkt_len_var, fin_flag_count, rst_flag_count, 
                       psh_flag_count, ack_flag_count, urg_flag_count, down_up_ratio, init_win_bytes_fwd, 
                       init_win_bytes_bwd, act_data_pkt_fwd, min_seg_size_fwd, active_mean, active_std, 
                       active_max, active_min, idle_std, has_inf_flow_bytes, has_inf_flow_pkts]]

        # Convert to appropriate types
        try:
            input_data = [[float(x) if '.' in x else int(x) for x in sublist] for sublist in input_data]
        except ValueError:
            st.error("Please enter valid numeric inputs.")
            return

        # Prediction on manual input
        if st.button("Predict"):
            with st.spinner("Predicting..."):
                result = zerodayattack_prediction(input_data)
                st.success(f"Prediction: {result[0]}")

if __name__ == "__main__":
    main()
