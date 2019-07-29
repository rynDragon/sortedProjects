
        ///////////////////////// Listen_State_in()
        /// <summary> This function processes input from IP while in Listen State</summary>
        private void listen_state_in(IP_PRIMITIVE iprim, SEGMENT s)
        {
            RETRANSMISSION_TIMER rprim;

            if (s.getFlag(SEGMENT.SYN) == SEGMENT.SYN)
            {
                // SYN segment

                // save off incoming information from remote TCP's SYN
                init_rcv_seq_ = s.SeqNum;
                rcv_next_ = s.SeqNum + 1;
                rcv_window_ = s.Window;
                source_port_ = s.DestPort;
                dest_port_ = s.SourcePort;
                dest_addr_ = iprim.SourceAddr;

                // now format ack reply
                format(s, (sbyte) (SEGMENT.SYN + SEGMENT.ACK));

                // and send ack in primitive to remote side, reusing the iprim
                iprim.format(source_port_, source_addr_, dest_port_, dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                DRIVER.send(DRIVER.tcpoutQ, iprim);

                // indicate iprim is given away, to ensure no deletion
                iprim = null;

                // set new state
                state_ = STATE.SYN_RCVD_STATE;

                // Start retransmission timer
                rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER, DRIVER.gl_time(),
                    DRIVER.gl_time() + rto_);
                DRIVER.send(DRIVER.timerQ, rprim);
            }
            else
                MyPrint.SmartWrite("TCP_input: LISTEN: Unknown Prim\n");

            // eliminate any pointers lying around
            rprim = null;
        }

        ///////////////////////// syn_sent_State_in() Template
        /// <summary> This function processes input in the form of an IP_PRIMITVE (iprim) with a
        /// previously attached segment s.
        /// </summary>
        private void syn_sent_state_in(IP_PRIMITIVE iprim, SEGMENT s)
        {
            RETRANSMISSION_TIMER rprim;

            //  Check the TCP Segment type to determine what was received
            if (s.getFlag(SEGMENT.SYN) == SEGMENT.SYN)
            {
                // save off incoming information from remote TCP's segment (such as ack-num)
                rcv_next_ = s.SeqNum + 1;

                // increment send sequence
                send_next_++;

                // now format ack reply
                format(s, (sbyte) (SEGMENT.ACK));

                // and send ack in primitive to remote side, reusing the iprim
                iprim.format(source_port_, source_addr_, dest_port_, dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                DRIVER.send(DRIVER.tcpoutQ, iprim);

                // indicate iprim is given away, to ensure no deletion
                iprim = null;

                // set new state
                state_ = STATE.ESTABLISHED_STATE; //SYN_RCVD_STATE;

                PRIMITIVE aprim = new PRIMITIVE(local_connect_, PRIMITIVE.PRIM_TYPE.OPEN_RESPONSE, 0,
                    PRIMITIVE.STATUS.SUCCESS);
                DRIVER.send(DRIVER.appinQ, aprim);

                // Start retransmission timer (if appropriate)
                rprim = new RETRANSMISSION_TIMER(local_connect_,
                    PRIMITIVE.PRIM_TYPE.CLEAR_RETX_TIMER /**.SET_RETX_TIMER**/, DRIVER.gl_time(),
                    DRIVER.gl_time() + rto_);
                DRIVER.send(DRIVER.timerQ, rprim);
            }
            else // Primitive not recognized yet
                MyPrint.SmartWrite("TCP_input: CLOSED_STATE: Unknown Prim\n");

            // eliminate any pointers lying around
            rprim = null;
            // capture the remotes window
            windowSize = s.Window;
            iprim = null;
        }

        ///////////////////////////// Process TCP Output
        /// <summary>  Process TCP Output()
        /// This function processes all primitives from the
        /// application or timer task,
        /// which are destined for transmission to the remote side.
        /// </summary>
        public virtual void process_tcp_output(PRIMITIVE prim)
        {
            // Print the state first for debug purposes
            MyPrint.SmartWriteLine("\n    TCP State:" + state_name[(int) state_]);

            switch (state_)
            {
                case STATE.CLOSED_STATE:
                    closed_state_out(prim);
                    break;

                case STATE.SYN_SENT_STATE:
                    syn_sent_state_out(prim);
                    break;

                case STATE.ESTABLISHED_STATE:
                    established_state_out(prim);
                    break;
                    
                case STATE.TIME_WAIT_STATE:
                    time_wait_state_out(prim);
                    break;

                default: // any other state for now goes here
                    MyPrint.SmartWrite("TCP Output: State Not Supported Yet!\n");
                    //prim.print(PRIMITIVE.L2DEBUG);
                    break;
            } /* endswitch state */
            // if prim still hanging around, delete it.
            prim = null;
        } /* end process_tcp_output */

        ////////////////////////// Closed_State_Out()
        /// <summary> This processes output from the Application in Closed State</summary>
        private void closed_state_out(PRIMITIVE prim)
        {
            IP_PRIMITIVE iprim;
            OPEN_PRIMITIVE oprim;
            RETRANSMISSION_TIMER rprim;

            switch (prim.PrimType)
            {
                case PRIMITIVE.PRIM_TYPE.OPEN:
                    // save off info from primitive
                    oprim = (OPEN_PRIMITIVE) prim;
                    source_port_ = oprim.SourcePort;
                    send_window_ = (short) oprim.ByteCount;
                    dest_port_ = oprim.DestPort;
                    dest_addr_.set_IP_addr(oprim.DestAddr);
                    if (oprim.OpenType == OPEN_PRIMITIVE.OPEN_TYPE.ACTIVE_OPEN)
                    {
                        // Format the SYNCHRONIZE segment
                        SEGMENT s = new SEGMENT();
                        format(s, SEGMENT.SYN);
                        // Format the IP_SEND primitive for IP
                        iprim = new IP_PRIMITIVE(PRIMITIVE.PRIM_TYPE.IP_SEND, source_port_, source_addr_, dest_port_,
                            dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                        DRIVER.send(DRIVER.tcpoutQ, iprim);
                        // Set the new state
                        state_ = STATE.SYN_SENT_STATE;
                        // Start retransmission timer
                        rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER,
                            DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                        DRIVER.send(DRIVER.timerQ, rprim);
                    }
                    // Passive open - wait for remote connection
                    else
                        state_ = STATE.LISTEN_STATE;
                    break;

                default:
                    MyPrint.SmartWriteLine("TCP Output Closed State: Received Prim: " + prim.PrimType);
                    //prim.print(PRIMITIVE.L2DEBUG);
                    break;
            } /* endswitch primtype */
            rprim = null;
            iprim = null;
            oprim = null;
        }

        ////////////////////////// Syn_Sent_State_Out()
        /// <summary> This processes output from the Application in CLOSED_STATE</summary>
        private void syn_sent_state_out(PRIMITIVE prim)
        {
            IP_PRIMITIVE iprim;
            RETRANSMISSION_TIMER rprim;
            PRIMITIVE aprim;

            switch (prim.PrimType)
            {
                // First check the primitive type, and act based on that:
                //case PRIMITIVE.PRIM_TYPE.SEND:
                case PRIMITIVE.PRIM_TYPE.EXPIRE_RETX_TIMER:
                    // Format a segment for transmission:
                    SEGMENT s = new SEGMENT();
                    if (RETRANSMISSION_COUNTER == 3)
                    {
                        // retransmission have been sent so we send a reset to the output queue
                        format(s, SEGMENT.RST);
                        iprim = new IP_PRIMITIVE(PRIMITIVE.PRIM_TYPE.IP_SEND, source_port_, source_addr_, dest_port_,
                            dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                        DRIVER.send(DRIVER.tcpoutQ, iprim);

                        // send an abort primative TCP->APP
                        aprim = new PRIMITIVE(local_connect_, PRIMITIVE.PRIM_TYPE.ABORT);
                        DRIVER.send(DRIVER.appinQ, aprim);
                    }
                    else
                    {
                        format(s, SEGMENT.SYN);

                        // Format the IP_SEND primitive for IP
                        iprim = (IP_PRIMITIVE) prim;
                        DRIVER.send(DRIVER.tcpoutQ, iprim);

                        // Set the new state if appropriate
                        state_ = STATE.SYN_SENT_STATE;

                        // Start retransmission timer
                        rto_ *= 2;
                        RETRANSMISSION_COUNTER += 1;
                        rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER,
                            DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                        DRIVER.send(DRIVER.timerQ, rprim);
                    }
                    break;

                default: // we receive prim type not yet handled
                    MyPrint.SmartWriteLine("TCP Output SYN_SENT_STATE State: Received Prim: " + prim.PrimType);
                    //prim.print(PRIMITIVE.L2DEBUG);
                    break;
            } //  endswitch primtype 
            // get rid of any prims lying around
            rprim = null;
            aprim = null;
        }

        ////////////////////////// established_state_out
        /// <summary> This processes output from the Application in established State</summary>
        private void established_state_out(PRIMITIVE prim)
        {
            RETRANSMISSION_TIMER rprim;

            switch (prim.PrimType)
            {
                case PRIMITIVE.PRIM_TYPE.SEND:

                    // Cast the primative as an ip_primative
                    IP_PRIMITIVE iprim = (IP_PRIMITIVE) prim;
                    
                    // Set the prim type as IP_SEND
                    iprim.PrimType = PRIMITIVE.PRIM_TYPE.IP_SEND;
                    
                    // Format the primative with improved format method
                    format(iprim.Segment, SEGMENT.ACK);
                    
                    // fix for the null pointer issues in the header
                    iprim.SourcePort = source_port_;
                    iprim.SourceAddr = source_addr_;
                    iprim.DestPort = dest_port_;
                    iprim.DestAddr = dest_addr_;
                    
                    if (iprim.Segment.Data.Length > windowSize)
                    {
                        partialPacket = iprim.Segment.Data;
                        iprim.Segment.Data = iprim.Segment.Data.Substring(0, windowSize);
                        partialPacket = partialPacket.Substring(windowSize);
                    }
                    
                    // Adjust byte_count
                    iprim.ByteCount = SEGMENT.TCP_HDR_LEN + iprim.Segment.Data.Length;
                    
                    // finally IP <-- TCP
                    DRIVER.send(DRIVER.tcpoutQ, iprim);

                    //send_window_ -= (short)iprim.Segment.Data.Length;
                    send_next_ += iprim.Segment.Data.Length;
                    
                    // set the retransmission timmer
                    rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER,
                        DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                    DRIVER.send(DRIVER.timerQ, rprim);
                    
                    break;

                case PRIMITIVE.PRIM_TYPE.CLOSE:
                    // Set the new state if appropriate
                    state_ = STATE.FIN_WAIT_1_STATE;

                    // create a new IP_PRIMITIVE with a FIN segment type
                    SEGMENT s = new SEGMENT();
                    format(s, SEGMENT.FIN);
                    iprim = new IP_PRIMITIVE(PRIMITIVE.PRIM_TYPE.IP_SEND, source_port_, source_addr_, dest_port_,
                        dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                    
                    // add the new PRIMITIVE to the TCP OUTPUT queue
                    DRIVER.send(DRIVER.tcpoutQ, iprim);
                    
                    // FIN takes one byte in sequence number space
                    send_next_ += 1;

                    // set the retransmission timmer
                    rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER,
                        DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                    DRIVER.send(DRIVER.timerQ, rprim);

                    break;

                case PRIMITIVE.PRIM_TYPE.RECEIVE:
                    send_window_ += (Int16)prim.byte_count_;
                    
                    SEGMENT segment = new SEGMENT();

                    format(segment, SEGMENT.ACK);
                    
                    DRIVER.send(DRIVER.tcpoutQ, new IP_PRIMITIVE(
                        PRIMITIVE.PRIM_TYPE.IP_SEND
                        , source_port_
                        , source_addr_
                        , dest_port_
                        , dest_addr_
                        , SEGMENT.TCP_HDR_LEN, segment
                        )
                    );
                    
                    break;
                    
                default: // we receive prim type not yet handled
                    MyPrint.SmartWriteLine("TCP Output CONNECTED_STATE State: Received Prim: " + prim.PrimType);
                    //prim.print(PRIMITIVE.L2DEBUG);
                    break;
            }
        }

        ////////////////////////// established_state_in
        /// <summary> This processes input from the remote. 
        /// receive an ack and save off the size of the received packet
        /// minus the header size to increment the received byte count.
        /// clear the timer
        /// </summary>
        private void established_state_in(PRIMITIVE prim, SEGMENT s)
        {
            RETRANSMISSION_TIMER rprim;

            if (s.getFlag(SEGMENT.ACK) == SEGMENT.ACK)
            {
                if (prim.byte_count_ == 20)
                {
                    rcv_next_ += prim.byte_count_ - 20;

                    windowSize = s.Window;

                    if (!string.IsNullOrEmpty(partialPacket))
                    {
                        IP_PRIMITIVE iprim = new IP_PRIMITIVE(
                            PRIMITIVE.PRIM_TYPE.IP_SEND
                            , source_port_
                            , source_addr_
                            , dest_port_
                            , dest_addr_
                            , SEGMENT.TCP_HDR_LEN
                            , new SEGMENT());
                        
                        // Format the primative with improved format method
                        format(iprim.Segment, SEGMENT.ACK);

                        if (partialPacket.Length > windowSize)
                        {
                            iprim.Segment.Data = partialPacket.Substring(0, windowSize);
                            partialPacket = partialPacket.Substring(windowSize);
                        }
                        else
                        {
                            iprim.Segment.Data = partialPacket;
                            partialPacket = "";
                        }
                        
                        // Adjust byte_count
                        iprim.ByteCount = SEGMENT.TCP_HDR_LEN + iprim.Segment.Data.Length;
                    
                        // finally IP <-- TCP
                        DRIVER.send(DRIVER.tcpoutQ, iprim);

                        //send_window_ -= (short)iprim.Segment.Data.Length;
                        send_next_ += iprim.Segment.Data.Length;
                    
                        // set the retransmission timmer
                        rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER,
                            DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                        DRIVER.send(DRIVER.timerQ, rprim);
                    }
                    // clear the timer after saving off the bytecount
                    rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.CLEAR_RETX_TIMER,
                        DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                    DRIVER.send(DRIVER.timerQ, rprim);

                    s = null;
                }
                else if (prim.byte_count_ > 20 && send_window_ >= prim.byte_count_ - 20)
                {
                    if (s.SeqNum == rcv_next_)
                    {
                        rcv_next_ += prim.byte_count_ - 20;

                        send_window_ -= (Int16) (prim.byte_count_ - 20);

                        DRIVER.send(DRIVER.appinQ
                            , new IP_PRIMITIVE(local_connect_, PRIMITIVE.PRIM_TYPE.RECEIVE_RESPONSE, prim.byte_count_ - 20, s));

                        s = new SEGMENT();
                        format(s, SEGMENT.ACK);

                        // and send ack in primitive to remote side, reusing the prim
                        ((IP_PRIMITIVE) prim).format(source_port_, source_addr_, dest_port_, dest_addr_,
                            SEGMENT.TCP_HDR_LEN, s);
                        DRIVER.send(DRIVER.tcpoutQ, prim);
                    }
                    else
                    {
                        s = new SEGMENT();
                        format(s, SEGMENT.ACK);
                    
                        // and send ack in primitive to remote side, reusing the prim
                        ((IP_PRIMITIVE) prim).format(source_port_, source_addr_, dest_port_, dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                        DRIVER.send(DRIVER.tcpoutQ, prim);
                    }
                }
                else if (prim.byte_count_ > 20 && send_window_ < prim.byte_count_ - 20)
                {
                    s = new SEGMENT();
                    format(s, SEGMENT.ACK);

                    // and send ack in primitive to remote side, reusing the prim
                    ((IP_PRIMITIVE) prim).format(source_port_, source_addr_, dest_port_, dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                    DRIVER.send(DRIVER.tcpoutQ, prim);
                }
            }
            prim = null;
            s = null;
        }

        ////////////////////////// fin_wait_1_state_in
        /// <summary> This processes input from the remote in FIN_WAIT_1_STATE
        /// receiving an ACK from the remote and moving
        /// into the next state: FIN_WAIT_2_STATE.
        /// clear the timer.
        /// </summary>
        private void fin_wait_1_state_in(PRIMITIVE prim, SEGMENT s)
        {
            if (s.getFlag(SEGMENT.ACK) == SEGMENT.ACK)
            {
                state_ = STATE.FIN_WAIT_2_STATE;

                RETRANSMISSION_TIMER rprim;
                rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.CLEAR_RETX_TIMER, DRIVER.gl_time(),
                    DRIVER.gl_time() + rto_);
                DRIVER.send(DRIVER.timerQ, rprim);
            }
        }

        ////////////////////////// fin_wait_1_state_in
        /// <summary> This processes input from the remote in FIN_WAIT_2_STATE
        /// receive a FIN from the remote and moving
        /// into the next state: TIME_WAIT_STATE.
        /// send an ACK in response (to the FIN) and
        /// set the retransmission timer.
        /// </summary>
        private void fin_wait_2_state_in(PRIMITIVE prim, SEGMENT s)
        {
            if (s.getFlag(SEGMENT.FIN) == SEGMENT.FIN)
            {
                state_ = STATE.TIME_WAIT_STATE;
                //MyPrint.SmartWriteLine(state_.ToString());

                // increment the received in response to a FIN which is one set bit that takes one byte in the data
                rcv_next_ += 1;

                // create a new dataless ACK to send to the remote
                s = new SEGMENT();
                format(s, SEGMENT.ACK);
                IP_PRIMITIVE iprim = new IP_PRIMITIVE(PRIMITIVE.PRIM_TYPE.IP_SEND, source_port_, source_addr_,
                    dest_port_, dest_addr_, SEGMENT.TCP_HDR_LEN, s);
                DRIVER.send(DRIVER.tcpoutQ, iprim);

                // set the retransmission timer
                RETRANSMISSION_TIMER rprim = new RETRANSMISSION_TIMER(local_connect_, PRIMITIVE.PRIM_TYPE.SET_RETX_TIMER, DRIVER.gl_time(), DRIVER.gl_time() + rto_);
                DRIVER.send(DRIVER.timerQ, rprim);
            }
        }
        
        ////////////////////////// time_wait_state_out
        /// <summary> This processes output from the Application in TIME_WAIT_STATE
        /// we receive a timeout from the timer and set the state to CLOSED_STATE
        /// </summary>
        private void time_wait_state_out(PRIMITIVE prim)
        {
            if (prim.prim_type_ == PRIMITIVE.PRIM_TYPE.EXPIRE_RETX_TIMER)
            {
                // change state to: CLOSED_STATE
                state_ = STATE.CLOSED_STATE;
                
                // notify the application of the state change to close
                DRIVER.send(DRIVER.appinQ, new PRIMITIVE(local_connect_, PRIMITIVE.PRIM_TYPE.CLOSE_RESPONSE, 0,
                    PRIMITIVE.STATUS.SUCCESS));
            }
        }