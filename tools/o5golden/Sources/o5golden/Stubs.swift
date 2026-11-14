// What the copied OmnipodKit files need from the rest of OmnipodKit and
// LoopKit, cut down to what they use.
import Foundation
import os.log

extension OSLog {
    convenience init(category: String) { self.init(subsystem: "o5golden", category: category) }
    func `default`(_ message: StaticString, _ args: CVarArg...) {}
    func info(_ message: StaticString, _ args: CVarArg...) {}
    func error(_ message: StaticString, _ args: CVarArg...) {}
    func debug(_ message: StaticString, _ args: CVarArg...) {}
    func bleDebug(_ message: StaticString, _ args: CVarArg...) {}
}

enum PodProtocolError: Error {
    case pairingException(String)
    case messageIOException(String)
    case incorrectPacketException(Data, Int)
    case invalidCrc(payloadCrc: Data, computedCrc: Data)
    case couldNotParseMessageException(String)
    case invalidLTKKey(String)
}

// From OmnipodKit's O5LTKExchanger.swift.
enum O5LTKExchanger {
    static let FIRMWARE_ID = Data(hex: "9b0ab96a76f4")

    static func crc16XMODEM(_ data: Data) -> UInt16 {
        var crc: UInt16 = 0x0000
        for byte in data {
            crc ^= UInt16(byte) << 8
            for _ in 0..<8 {
                crc = crc & 0x8000 != 0 ? (crc << 1) ^ 0x1021 : crc << 1
            }
        }
        return crc
    }
}

// From OmnipodKit's BlePodProfile.swift.
struct BlePacketLayout {
    let maxPayloadSize: Int
    let maxFragments: Int
    let firstPacketHeaderSizeWithoutMiddlePackets: Int
    let firstPacketHeaderSizeWithMiddlePackets: Int
    let lastPacketHeaderSize: Int

    var firstPacketCapacityWithoutMiddlePackets: Int { maxPayloadSize - firstPacketHeaderSizeWithoutMiddlePackets }
    var firstPacketCapacityWithMiddlePackets: Int { maxPayloadSize - firstPacketHeaderSizeWithMiddlePackets }
    var firstPacketCapacityWithOptionalPlusOnePacket: Int { firstPacketCapacityWithMiddlePackets }
    var middlePacketCapacity: Int { maxPayloadSize - 1 }
    var lastPacketCapacity: Int { maxPayloadSize - lastPacketHeaderSize }
}

let o5Layout = BlePacketLayout(maxPayloadSize: 244, maxFragments: 15, firstPacketHeaderSizeWithoutMiddlePackets: 7,
                               firstPacketHeaderSizeWithMiddlePackets: 2, lastPacketHeaderSize: 6)

// From OmnipodKit's Id.swift, without the controller-id allocation.
class Id: Equatable {
    static func fromUInt32(_ v: UInt32) -> Id { Id(Data(bigEndian: v)) }
    let address: Data
    init(_ address: Data) { self.address = address.count == 4 ? address : Data(count: 4) }
    func toUInt32() -> UInt32 { address.toBigEndian(UInt32.self) }
    static func == (lhs: Id, rhs: Id) -> Bool { lhs.address == rhs.address }
}
